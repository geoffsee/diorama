use std::sync::Arc;

use diorama_apiserver::client::KubernetesApiClient;
use serde_json::{Value, json};

use crate::error::ControllerError;
use crate::workload::{ReconcileOutcome, adopt_and_release_pods};

#[derive(Clone, Debug)]
pub struct ReplicationControllerReconciler {
    client: Arc<KubernetesApiClient>,
}

impl ReplicationControllerReconciler {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    /// Reconciles all `ReplicationControllers` in the specified namespace.
    pub async fn reconcile_all(
        &self,
        namespace: &str,
    ) -> Result<ReconcileOutcome, ControllerError> {
        let list = self
            .client
            .list_replicationcontrollers(namespace)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: "replicationcontrollers".to_string(),
                reason: e.to_string(),
            })?;

        let items = list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut count = 0;
        let mut errors = Vec::new();
        for rc in items {
            match self.reconcile_rc(namespace, &rc).await {
                Ok(_) => count += 1,
                Err(err) => errors.push(err.to_string()),
            }
        }

        Ok(ReconcileOutcome {
            reconciled: count,
            errors,
        })
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
                        "apiVersion": "v1",
                        "kind": "ReplicationController",
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

    /// Reconciles a single `ReplicationController` by adopting/releasing and scaling child Pods.
    pub async fn reconcile_rc(
        &self,
        namespace: &str,
        rc: &Value,
    ) -> Result<Value, ControllerError> {
        let cfg = parse_rc_config(rc)?;

        let owned_pods = adopt_and_release_pods(
            &self.client,
            namespace,
            "v1",
            "ReplicationController",
            cfg.name,
            cfg.uid,
            cfg.deleting,
            cfg.selector,
        )
        .await?;
        let current_count = owned_pods.len();

        if !cfg.deleting {
            if current_count < cfg.desired_replicas {
                self.scale_up_pods(
                    namespace,
                    cfg.name,
                    cfg.uid,
                    current_count,
                    cfg.desired_replicas,
                    &cfg.template,
                )
                .await?;
            } else if current_count > cfg.desired_replicas {
                self.scale_down_pods(namespace, &owned_pods, cfg.desired_replicas)
                    .await?;
            }
        }

        let updated_owned_pods = if current_count == cfg.desired_replicas || cfg.deleting {
            owned_pods
        } else {
            adopt_and_release_pods(
                &self.client,
                namespace,
                "v1",
                "ReplicationController",
                cfg.name,
                cfg.uid,
                cfg.deleting,
                cfg.selector,
            )
            .await?
        };
        let actual_replicas = updated_owned_pods.len();
        let ready_replicas = updated_owned_pods
            .iter()
            .filter(|p| super::is_pod_ready(p))
            .count();
        let observed_gen = rc
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(1)
            .max(1);

        let mut updated_rc = rc.clone();
        apply_rc_status(
            &mut updated_rc,
            actual_replicas,
            ready_replicas,
            observed_gen,
        );

        if updated_rc.get("status") == rc.get("status") {
            return Ok(updated_rc);
        }

        self.client
            .update_replicationcontroller(namespace, cfg.name, updated_rc)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("replicationcontrollers/{}", cfg.name),
                reason: e.to_string(),
            })
    }
}

struct RcConfig<'a> {
    name: &'a str,
    uid: &'a str,
    deleting: bool,
    desired_replicas: usize,
    selector: Option<&'a Value>,
    template: Value,
}

fn parse_rc_config(rc: &Value) -> Result<RcConfig<'_>, ControllerError> {
    let name = rc
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .ok_or_else(|| ControllerError::InvalidConfiguration {
            field: "metadata.name".to_string(),
            reason: "ReplicationController missing metadata.name".to_string(),
        })?;
    let uid = rc
        .get("metadata")
        .and_then(|m| m.get("uid"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let deleting = rc
        .pointer("/metadata/deletionTimestamp")
        .and_then(Value::as_str)
        .is_some();
    let desired_replicas = rc
        .get("spec")
        .and_then(|s| s.get("replicas"))
        .and_then(Value::as_i64)
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(1);
    let selector = rc.pointer("/spec/selector");
    let template = rc
        .get("spec")
        .and_then(|s| s.get("template"))
        .cloned()
        .unwrap_or_else(|| json!({ "spec": { "containers": [] } }));
    Ok(RcConfig {
        name,
        uid,
        deleting,
        desired_replicas,
        selector,
        template,
    })
}

fn apply_rc_status(
    updated_rc: &mut Value,
    actual_replicas: usize,
    ready_replicas: usize,
    observed_gen: i64,
) {
    if let Some(status) = updated_rc.get_mut("status").and_then(Value::as_object_mut) {
        status.insert("replicas".to_string(), json!(actual_replicas));
        status.insert("fullyLabeledReplicas".to_string(), json!(actual_replicas));
        status.insert("readyReplicas".to_string(), json!(ready_replicas));
        status.insert("availableReplicas".to_string(), json!(ready_replicas));
        status.insert("observedGeneration".to_string(), json!(observed_gen));
    } else if let Some(rc_obj) = updated_rc.as_object_mut() {
        rc_obj.insert(
            "status".to_string(),
            json!({
                "replicas": actual_replicas,
                "fullyLabeledReplicas": actual_replicas,
                "readyReplicas": ready_replicas,
                "availableReplicas": ready_replicas,
                "observedGeneration": observed_gen
            }),
        );
    }
}
