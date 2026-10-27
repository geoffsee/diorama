use std::sync::Arc;

use diorama_apiserver::client::KubernetesApiClient;
use serde_json::{Map, Value, json};

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
        p: ScalePodsParams<'_>,
    ) -> Result<Option<String>, ControllerError> {
        let mut template_labels = p
            .template
            .get("metadata")
            .and_then(|m| m.get("labels"))
            .cloned()
            .unwrap_or_else(|| json!({}));

        if let Some(hash) = p
            .rs_labels
            .and_then(|l| l.get("pod-template-hash"))
            .and_then(Value::as_str)
            && let Some(obj) = template_labels.as_object_mut()
        {
            obj.entry("pod-template-hash".to_string())
                .or_insert_with(|| json!(hash));
        }

        let template_spec = p
            .template
            .get("spec")
            .cloned()
            .unwrap_or_else(|| json!({ "containers": [] }));

        let needed = p.desired_replicas.saturating_sub(p.current_count);
        let mut created = 0;
        let mut idx = 0;
        let mut create_error = None;

        while created < needed {
            let pod_name = format!("{}-{idx}", p.name);
            idx += 1;
            if self.client.get_pod(p.namespace, &pod_name).await.is_ok() {
                continue;
            }

            let new_pod = json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": pod_name,
                    "namespace": p.namespace,
                    "labels": template_labels,
                    "ownerReferences": [{
                        "apiVersion": "apps/v1",
                        "kind": "ReplicaSet",
                        "name": p.name,
                        "uid": p.uid,
                        "controller": true,
                        "blockOwnerDeletion": true
                    }]
                },
                "spec": template_spec,
                "status": {
                    "phase": "Pending"
                }
            });

            match self.client.create_pod(p.namespace, new_pod).await {
                Ok(_) => {
                    created += 1;
                },
                Err(err) => {
                    create_error = Some(err.to_string());
                    break;
                },
            }
        }
        Ok(create_error)
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

        let mut creation_error = None;
        if !deleting {
            if current_count < desired_replicas {
                let rs_labels = replicaset.pointer("/metadata/labels");
                creation_error = self
                    .scale_up_pods(ScalePodsParams {
                        namespace,
                        name,
                        uid,
                        current_count,
                        desired_replicas,
                        template: &template,
                        rs_labels,
                    })
                    .await?;
            } else if current_count > desired_replicas {
                self.scale_down_pods(namespace, &owned_pods, desired_replicas)
                    .await?;
            }
        }
        let updated_owned_pods =
            if (current_count == desired_replicas && creation_error.is_none()) || deleting {
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
        let fully_labeled_replicas = count_fully_labeled(&updated_owned_pods, &template);
        let observed_generation = replicaset
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(1);

        let mut updated_rs = replicaset.clone();
        let metrics = RsStatusMetrics {
            actual_replicas,
            fully_labeled_replicas,
            ready_replicas,
            observed_generation,
        };
        apply_rs_status(&mut updated_rs, &metrics, creation_error.as_deref());

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

struct ScalePodsParams<'a> {
    namespace: &'a str,
    name: &'a str,
    uid: &'a str,
    current_count: usize,
    desired_replicas: usize,
    template: &'a Value,
    rs_labels: Option<&'a Value>,
}

fn count_fully_labeled(pods: &[Value], template: &Value) -> usize {
    let tpl_labels = template
        .pointer("/metadata/labels")
        .and_then(Value::as_object);
    pods.iter()
        .filter(|p| {
            if let Some(expected) = tpl_labels {
                let p_labels = p.pointer("/metadata/labels").and_then(Value::as_object);
                expected
                    .iter()
                    .all(|(k, v)| p_labels.and_then(|l| l.get(k)) == Some(v))
            } else {
                true
            }
        })
        .count()
}

struct RsStatusMetrics {
    actual_replicas: usize,
    fully_labeled_replicas: usize,
    ready_replicas: usize,
    observed_generation: i64,
}

fn apply_rs_status(
    updated_rs: &mut Value,
    metrics: &RsStatusMetrics,
    creation_error: Option<&str>,
) {
    if let Some(status) = updated_rs.get_mut("status").and_then(Value::as_object_mut) {
        status.insert("replicas".to_string(), json!(metrics.actual_replicas));
        status.insert(
            "fullyLabeledReplicas".to_string(),
            json!(metrics.fully_labeled_replicas),
        );
        status.insert("readyReplicas".to_string(), json!(metrics.ready_replicas));
        status.insert(
            "availableReplicas".to_string(),
            json!(metrics.ready_replicas),
        );
        status.insert(
            "observedGeneration".to_string(),
            json!(metrics.observed_generation),
        );
        update_status_conditions(status, creation_error);
    } else if let Some(rs_obj) = updated_rs.as_object_mut() {
        let mut status_map = Map::new();
        status_map.insert("replicas".to_string(), json!(metrics.actual_replicas));
        status_map.insert(
            "fullyLabeledReplicas".to_string(),
            json!(metrics.fully_labeled_replicas),
        );
        status_map.insert("readyReplicas".to_string(), json!(metrics.ready_replicas));
        status_map.insert(
            "availableReplicas".to_string(),
            json!(metrics.ready_replicas),
        );
        status_map.insert(
            "observedGeneration".to_string(),
            json!(metrics.observed_generation),
        );
        update_status_conditions(&mut status_map, creation_error);
        rs_obj.insert("status".to_string(), Value::Object(status_map));
    }
}

fn update_status_conditions(status: &mut Map<String, Value>, creation_error: Option<&str>) {
    let mut conditions: Vec<Value> = status
        .get("conditions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if let Some(err_msg) = creation_error {
        let existing = conditions
            .iter()
            .find(|c| c.get("type").and_then(Value::as_str) == Some("ReplicaFailure"));

        let last_transition_time = if let Some(existing) = existing
            && existing.get("status").and_then(Value::as_str) == Some("True")
            && let Some(t) = existing.get("lastTransitionTime").and_then(Value::as_str)
        {
            t.to_string()
        } else {
            diorama_apiserver::time::now_rfc3339()
        };

        conditions.retain(|c| c.get("type").and_then(Value::as_str) != Some("ReplicaFailure"));
        conditions.push(json!({
            "type": "ReplicaFailure",
            "status": "True",
            "lastTransitionTime": last_transition_time,
            "reason": "FailedCreate",
            "message": err_msg,
        }));
        status.insert("conditions".to_string(), Value::Array(conditions));
    } else if status.contains_key("conditions") {
        conditions.retain(|c| c.get("type").and_then(Value::as_str) != Some("ReplicaFailure"));
        status.insert("conditions".to_string(), Value::Array(conditions));
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
