use std::sync::Arc;

use diorama_apiserver::ApiserverError;
use diorama_apiserver::client::KubernetesApiClient;
use serde_json::{Value, json};

use crate::error::ControllerError;
use crate::workload::ReconcileOutcome;

#[derive(Clone, Debug)]
pub struct StatefulSetReconciler {
    client: Arc<KubernetesApiClient>,
}

impl StatefulSetReconciler {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    /// Reconciles all `StatefulSets` in the specified namespace.
    pub async fn reconcile_all(
        &self,
        namespace: &str,
    ) -> Result<ReconcileOutcome, ControllerError> {
        let list = self
            .client
            .list_statefulsets(namespace)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: "statefulsets".to_string(),
                reason: e.to_string(),
            })?;

        let items = list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut count = 0;
        let mut errors = Vec::new();
        for ss in items {
            match self.reconcile_statefulset(namespace, &ss).await {
                Ok(_) => count += 1,
                Err(err) => errors.push(err.to_string()),
            }
        }

        Ok(ReconcileOutcome {
            reconciled: count,
            errors,
        })
    }

    async fn ensure_ordinal_pods(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        desired_replicas: usize,
        template_labels: &Value,
        template_spec: &Value,
    ) -> Result<(), ControllerError> {
        for idx in 0..desired_replicas {
            let pod_name = format!("{name}-{idx}");
            if self.client.get_pod(namespace, &pod_name).await.is_ok() {
                continue;
            }

            let mut pod_labels = template_labels.clone();
            if let Some(labels_obj) = pod_labels.as_object_mut() {
                labels_obj.insert(
                    "statefulset.kubernetes.io/pod-name".to_string(),
                    json!(pod_name),
                );
                labels_obj.insert(
                    "apps.kubernetes.io/pod-index".to_string(),
                    json!(idx.to_string()),
                );
            }

            let new_pod = json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": pod_name,
                    "namespace": namespace,
                    "labels": pod_labels,
                    "ownerReferences": [{
                        "apiVersion": "apps/v1",
                        "kind": "StatefulSet",
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
        Ok(())
    }

    async fn prune_excess_ordinal_pods(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        desired_replicas: usize,
    ) -> Result<(), ControllerError> {
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

        let mut to_delete: Vec<(usize, String)> = Vec::new();
        for pod in all_pods {
            let is_owned = pod
                .get("metadata")
                .and_then(|m| m.get("ownerReferences"))
                .and_then(Value::as_array)
                .is_some_and(|owners| {
                    owners.iter().any(|o| {
                        o.get("kind").and_then(Value::as_str) == Some("StatefulSet")
                            && (o.get("uid").and_then(Value::as_str) == Some(uid)
                                || o.get("name").and_then(Value::as_str) == Some(name))
                    })
                });

            if !is_owned {
                continue;
            }

            if let Some(pname) = pod
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
                && let Some(suffix) = pname.strip_prefix(&format!("{name}-"))
                && let Ok(idx) = suffix.parse::<usize>()
                && idx >= desired_replicas
            {
                to_delete.push((idx, pname.to_string()));
            }
        }

        // Delete in descending ordinal order (reverse order)
        to_delete.sort_by_key(|b| std::cmp::Reverse(b.0));
        for (_, pname) in to_delete {
            match self.client.delete_pod(namespace, &pname).await {
                Ok(()) | Err(ApiserverError::NotFound { .. }) => {},
                Err(err) => {
                    return Err(ControllerError::ReconciliationFailed {
                        resource: "statefulsets".to_string(),
                        reason: format!("failed to delete excess StatefulSet pod {pname}: {err}"),
                    });
                },
            }
        }
        Ok(())
    }

    /// Reconciles a single `StatefulSet` by maintaining ordered ordinal pods (name-0, name-1, etc.).
    pub async fn reconcile_statefulset(
        &self,
        namespace: &str,
        ss: &Value,
    ) -> Result<Value, ControllerError> {
        let name = ss
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ControllerError::InvalidConfiguration {
                field: "metadata.name".to_string(),
                reason: "StatefulSet missing metadata.name".to_string(),
            })?;

        let uid = ss
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let desired_replicas = ss
            .get("spec")
            .and_then(|s| s.get("replicas"))
            .and_then(Value::as_i64)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(1);

        let template = ss
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

        self.ensure_ordinal_pods(
            namespace,
            name,
            uid,
            desired_replicas,
            &template_labels,
            &template_spec,
        )
        .await?;

        self.prune_excess_ordinal_pods(namespace, name, uid, desired_replicas)
            .await?;

        let mut updated_ss = ss.clone();
        if let Some(status) = updated_ss.get_mut("status").and_then(Value::as_object_mut) {
            status.insert("replicas".to_string(), json!(desired_replicas));
            status.insert("currentReplicas".to_string(), json!(desired_replicas));
            status.insert("observedGeneration".to_string(), json!(1));
        } else if let Some(ss_obj) = updated_ss.as_object_mut() {
            ss_obj.insert(
                "status".to_string(),
                json!({
                    "replicas": desired_replicas,
                    "currentReplicas": desired_replicas,
                    "observedGeneration": 1
                }),
            );
        }

        self.client
            .update_statefulset(namespace, name, updated_ss)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("statefulsets/{name}"),
                reason: e.to_string(),
            })
    }
}
