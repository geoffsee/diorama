use std::sync::Arc;

use diorama_apiserver::client::KubernetesApiClient;
use serde_json::{Value, json};

use crate::error::ControllerError;
use crate::workload::ReconcileOutcome;

#[derive(Clone, Debug)]
pub struct DaemonSetReconciler {
    client: Arc<KubernetesApiClient>,
}

impl DaemonSetReconciler {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    /// Reconciles all `DaemonSets` in the specified namespace.
    pub async fn reconcile_all(
        &self,
        namespace: &str,
    ) -> Result<ReconcileOutcome, ControllerError> {
        let list = self.client.list_daemonsets(namespace).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "daemonsets".to_string(),
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
        for ds in items {
            match self.reconcile_daemonset(namespace, &ds).await {
                Ok(_) => count += 1,
                Err(err) => errors.push(err.to_string()),
            }
        }

        Ok(ReconcileOutcome {
            reconciled: count,
            errors,
        })
    }

    /// Reconciles a single `DaemonSet` by ensuring a node-level pod exists.
    pub async fn reconcile_daemonset(
        &self,
        namespace: &str,
        ds: &Value,
    ) -> Result<Value, ControllerError> {
        let name = ds
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ControllerError::InvalidConfiguration {
                field: "metadata.name".to_string(),
                reason: "DaemonSet missing metadata.name".to_string(),
            })?;

        let uid = ds
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let template = ds
            .get("spec")
            .and_then(|s| s.get("template"))
            .cloned()
            .unwrap_or_else(|| json!({ "spec": { "containers": [] } }));

        let template_labels = template
            .get("metadata")
            .and_then(|m| m.get("labels"))
            .cloned()
            .unwrap_or_else(|| json!({}));

        let template_spec = template
            .get("spec")
            .cloned()
            .unwrap_or_else(|| json!({ "containers": [] }));

        let pod_name = format!("{name}-node");

        // Idempotent creation: check if daemon pod already exists
        if self.client.get_pod(namespace, &pod_name).await.is_err() {
            let new_pod = json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": pod_name,
                    "namespace": namespace,
                    "labels": template_labels,
                    "ownerReferences": [{
                        "apiVersion": "apps/v1",
                        "kind": "DaemonSet",
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
        }

        // Update DaemonSet status
        let mut updated_ds = ds.clone();
        if let Some(status) = updated_ds.get_mut("status").and_then(Value::as_object_mut) {
            status.insert("desiredNumberScheduled".to_string(), json!(1));
            status.insert("currentNumberScheduled".to_string(), json!(1));
            status.insert("numberReady".to_string(), json!(1));
            status.insert("observedGeneration".to_string(), json!(1));
        } else if let Some(ds_obj) = updated_ds.as_object_mut() {
            ds_obj.insert(
                "status".to_string(),
                json!({
                    "desiredNumberScheduled": 1,
                    "currentNumberScheduled": 1,
                    "numberReady": 1,
                    "observedGeneration": 1
                }),
            );
        }

        if updated_ds.get("status") == ds.get("status") {
            return Ok(updated_ds);
        }

        self.client
            .update_daemonset(namespace, name, updated_ds)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("daemonsets/{name}"),
                reason: e.to_string(),
            })
    }
}
