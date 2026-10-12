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
    ) -> Result<Vec<Value>, ControllerError> {
        let pod_list = self.client.list_pods(namespace).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "pods".to_string(),
                reason: e.to_string(),
            }
        })?;

        let all_pods = pod_list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut owned_pods: Vec<Value> = all_pods
            .into_iter()
            .filter(|p| {
                let not_terminating = p
                    .get("metadata")
                    .and_then(|m| m.get("deletionTimestamp"))
                    .and_then(Value::as_str)
                    .is_none();
                not_terminating
                    && p.get("metadata")
                        .and_then(|m| m.get("ownerReferences"))
                        .and_then(Value::as_array)
                        .is_some_and(|owners| {
                            owners.iter().any(|o| {
                                o.get("kind").and_then(Value::as_str) == Some("ReplicaSet")
                                    && (o.get("uid").and_then(Value::as_str) == Some(uid)
                                        || o.get("name").and_then(Value::as_str) == Some(name))
                            })
                        })
            })
            .collect();

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
        owned_pods: Vec<Value>,
        desired_replicas: usize,
    ) -> Result<(), ControllerError> {
        for pod in owned_pods.into_iter().skip(desired_replicas) {
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

        let desired_replicas = replicaset
            .get("spec")
            .and_then(|s| s.get("replicas"))
            .and_then(Value::as_i64)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(1);

        let template = replicaset
            .get("spec")
            .and_then(|s| s.get("template"))
            .cloned()
            .unwrap_or_else(|| json!({ "spec": { "containers": [] } }));

        let owned_pods = self.get_owned_pods(namespace, name, uid).await?;
        let current_count = owned_pods.len();

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
            self.scale_down_pods(namespace, owned_pods, desired_replicas)
                .await?;
        }

        let updated_owned_pods = self.get_owned_pods(namespace, name, uid).await?;
        let ready_replicas = updated_owned_pods
            .iter()
            .take(desired_replicas)
            .filter(|p| super::is_pod_ready(p))
            .count();

        let mut updated_rs = replicaset.clone();
        if let Some(status) = updated_rs.get_mut("status").and_then(Value::as_object_mut) {
            status.insert("replicas".to_string(), json!(desired_replicas));
            status.insert("readyReplicas".to_string(), json!(ready_replicas));
            status.insert("availableReplicas".to_string(), json!(ready_replicas));
            status.insert("observedGeneration".to_string(), json!(1));
        } else if let Some(rs_obj) = updated_rs.as_object_mut() {
            rs_obj.insert(
                "status".to_string(),
                json!({
                    "replicas": desired_replicas,
                    "readyReplicas": ready_replicas,
                    "availableReplicas": ready_replicas,
                    "observedGeneration": 1
                }),
            );
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
