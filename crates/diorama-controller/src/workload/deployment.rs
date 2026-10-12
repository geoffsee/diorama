use std::sync::Arc;

use diorama_apiserver::client::KubernetesApiClient;
use serde_json::{Value, json};

use crate::error::ControllerError;
use crate::workload::ReconcileOutcome;

#[derive(Clone, Debug)]
pub struct DeploymentReconciler {
    client: Arc<KubernetesApiClient>,
}

impl DeploymentReconciler {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    /// Reconciles all Deployments in the specified namespace.
    pub async fn reconcile_all(
        &self,
        namespace: &str,
    ) -> Result<ReconcileOutcome, ControllerError> {
        let list = self.client.list_deployments(namespace).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "deployments".to_string(),
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
        for deployment in items {
            match self.reconcile_deployment(namespace, &deployment).await {
                Ok(_) => count += 1,
                Err(err) => errors.push(err.to_string()),
            }
        }

        Ok(ReconcileOutcome {
            reconciled: count,
            errors,
        })
    }

    async fn sync_child_replicaset(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        desired_replicas: i64,
        selector: Value,
        template: Value,
    ) -> Result<(), ControllerError> {
        let child_rs_name = format!("{name}-rs");
        let existing_rs = self
            .client
            .get_replicaset(namespace, &child_rs_name)
            .await
            .ok();

        if let Some(mut rs) = existing_rs {
            let current_replicas = rs
                .get("spec")
                .and_then(|s| s.get("replicas"))
                .and_then(Value::as_i64)
                .unwrap_or(1);

            if current_replicas != desired_replicas {
                if let Some(spec) = rs.get_mut("spec").and_then(Value::as_object_mut) {
                    spec.insert("replicas".to_string(), json!(desired_replicas));
                }
                self.client
                    .update_replicaset(namespace, &child_rs_name, rs)
                    .await
                    .map_err(|e| ControllerError::ReconciliationFailed {
                        resource: format!("replicasets/{child_rs_name}"),
                        reason: e.to_string(),
                    })?;
            }
        } else {
            let new_rs = json!({
                "apiVersion": "apps/v1",
                "kind": "ReplicaSet",
                "metadata": {
                    "name": child_rs_name,
                    "namespace": namespace,
                    "ownerReferences": [{
                        "apiVersion": "apps/v1",
                        "kind": "Deployment",
                        "name": name,
                        "uid": uid,
                        "controller": true,
                        "blockOwnerDeletion": true
                    }]
                },
                "spec": {
                    "replicas": desired_replicas,
                    "selector": selector,
                    "template": template
                }
            });

            self.client
                .create_replicaset(namespace, new_rs)
                .await
                .map_err(|e| ControllerError::ReconciliationFailed {
                    resource: format!("replicasets/{child_rs_name}"),
                    reason: e.to_string(),
                })?;
        }
        Ok(())
    }

    /// Reconciles a single `Deployment` object by ensuring its child `ReplicaSet` exists and matches spec.
    pub async fn reconcile_deployment(
        &self,
        namespace: &str,
        deployment: &Value,
    ) -> Result<Value, ControllerError> {
        let name = deployment
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ControllerError::InvalidConfiguration {
                field: "metadata.name".to_string(),
                reason: "Deployment missing metadata.name".to_string(),
            })?;

        let uid = deployment
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let desired_replicas = deployment
            .get("spec")
            .and_then(|s| s.get("replicas"))
            .and_then(Value::as_i64)
            .unwrap_or(1);

        let selector = deployment
            .get("spec")
            .and_then(|s| s.get("selector"))
            .cloned()
            .unwrap_or_else(|| json!({}));

        let template = deployment
            .get("spec")
            .and_then(|s| s.get("template"))
            .cloned()
            .unwrap_or_else(|| json!({ "spec": { "containers": [] } }));

        self.sync_child_replicaset(namespace, name, uid, desired_replicas, selector, template)
            .await?;

        let child_rs_name = format!("{name}-rs");
        let (raw_ready, raw_available) = self
            .resolve_replicas_status(namespace, &child_rs_name, name)
            .await;

        let ready_replicas = raw_ready.min(desired_replicas);
        let available_replicas = raw_available.min(desired_replicas);

        let mut updated_deployment = deployment.clone();
        if let Some(status) = updated_deployment
            .get_mut("status")
            .and_then(Value::as_object_mut)
        {
            status.insert("replicas".to_string(), json!(desired_replicas));
            status.insert("readyReplicas".to_string(), json!(ready_replicas));
            status.insert("availableReplicas".to_string(), json!(available_replicas));
            status.insert("updatedReplicas".to_string(), json!(desired_replicas));
            status.insert("observedGeneration".to_string(), json!(1));
        } else if let Some(dep_obj) = updated_deployment.as_object_mut() {
            dep_obj.insert(
                "status".to_string(),
                json!({
                    "replicas": desired_replicas,
                    "readyReplicas": ready_replicas,
                    "availableReplicas": available_replicas,
                    "updatedReplicas": desired_replicas,
                    "observedGeneration": 1
                }),
            );
        }

        self.client
            .update_deployment(namespace, name, updated_deployment)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("deployments/{name}"),
                reason: e.to_string(),
            })
    }

    async fn count_pod_ready_replicas(
        &self,
        namespace: &str,
        child_rs_name: &str,
        dep_name: &str,
    ) -> i64 {
        let Ok(pod_list) = self.client.list_pods(namespace).await else {
            return 0;
        };
        let items = pod_list.get("items").and_then(Value::as_array);
        let count = items
            .into_iter()
            .flatten()
            .filter(|p| {
                is_pod_owned_by_workload(p, child_rs_name, dep_name) && super::is_pod_ready(p)
            })
            .count();
        i64::try_from(count).unwrap_or(i64::MAX)
    }

    async fn resolve_replicas_status(
        &self,
        namespace: &str,
        child_rs_name: &str,
        dep_name: &str,
    ) -> (i64, i64) {
        let mut ready_replicas = 0;
        let mut available_replicas = 0;

        if let Ok(rs) = self.client.get_replicaset(namespace, child_rs_name).await {
            ready_replicas = rs
                .pointer("/status/readyReplicas")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            available_replicas = rs
                .pointer("/status/availableReplicas")
                .and_then(Value::as_i64)
                .unwrap_or(ready_replicas);
        }

        if ready_replicas == 0 {
            let pod_count = self
                .count_pod_ready_replicas(namespace, child_rs_name, dep_name)
                .await;
            ready_replicas = pod_count;
            available_replicas = pod_count;
        }

        (ready_replicas, available_replicas)
    }
}

fn is_pod_owned_by_workload(pod: &Value, child_rs_name: &str, dep_name: &str) -> bool {
    let Some(owners) = pod
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
    else {
        return false;
    };

    owners.iter().any(|o| {
        let kind = o.get("kind").and_then(Value::as_str);
        let name = o.get("name").and_then(Value::as_str);
        (kind == Some("ReplicaSet") && name == Some(child_rs_name))
            || (kind == Some("Deployment") && name == Some(dep_name))
    })
}
