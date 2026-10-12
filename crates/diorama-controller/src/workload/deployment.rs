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

        let mut updated_deployment = deployment.clone();
        if let Some(status) = updated_deployment
            .get_mut("status")
            .and_then(Value::as_object_mut)
        {
            status.insert("replicas".to_string(), json!(desired_replicas));
            status.insert("observedGeneration".to_string(), json!(1));
        } else if let Some(dep_obj) = updated_deployment.as_object_mut() {
            dep_obj.insert(
                "status".to_string(),
                json!({
                    "replicas": desired_replicas,
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
}
