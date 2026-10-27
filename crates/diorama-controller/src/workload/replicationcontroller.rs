use std::sync::Arc;

use diorama_apiserver::client::KubernetesApiClient;
use serde_json::{Map, Value, json};

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

    async fn is_rc_missing_or_terminating(&self, namespace: &str, name: &str) -> bool {
        match self.client.get_replicationcontroller(namespace, name).await {
            Ok(rc_val) => rc_val.pointer("/metadata/deletionTimestamp").is_some(),
            Err(_) => true,
        }
    }

    async fn disown_created_pods(&self, namespace: &str, rc_name: &str, pod_names: &[String]) {
        for pname in pod_names {
            self.strip_rc_owner_from_pod(namespace, rc_name, pname)
                .await;
        }
    }

    async fn strip_rc_owner_from_pod(&self, namespace: &str, rc_name: &str, pname: &str) {
        let Ok(mut pod) = self.client.get_pod(namespace, pname).await else {
            return;
        };
        let Some(owners) = pod
            .pointer_mut("/metadata/ownerReferences")
            .and_then(Value::as_array_mut)
        else {
            return;
        };
        let initial_len = owners.len();
        owners.retain(|o| !is_matching_rc_owner(o, rc_name));
        if owners.len() != initial_len {
            let _ = self.client.update_pod(namespace, pname, pod).await;
        }
    }

    async fn collect_batch_results(
        join_set: &mut tokio::task::JoinSet<(
            String,
            Result<Value, diorama_apiserver::ApiserverError>,
        )>,
        created: &mut usize,
        newly_created: &mut Vec<String>,
        create_error: &mut Option<String>,
    ) -> bool {
        let mut failed = false;
        while let Some(res) = join_set.join_next().await {
            let Ok((pname, create_res)) = res else {
                continue;
            };
            match create_res {
                Ok(_) => {
                    *created += 1;
                    newly_created.push(pname);
                },
                Err(err) => {
                    *create_error = Some(err.to_string());
                    failed = true;
                },
            }
        }
        failed
    }

    async fn scale_up_pods(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        current_count: usize,
        desired_replicas: usize,
        template: &Value,
    ) -> Result<Option<String>, ControllerError> {
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
        let mut create_error = None;
        let mut newly_created_pod_names = Vec::new();

        while created < needed {
            if self.is_rc_missing_or_terminating(namespace, name).await {
                break;
            }

            let batch_limit = (needed - created).min(20);
            let mut batch_candidates = Vec::with_capacity(batch_limit);
            while batch_candidates.len() < batch_limit {
                let candidate = format!("{name}-{idx}");
                idx += 1;
                if self.client.get_pod(namespace, &candidate).await.is_err() {
                    batch_candidates.push(candidate);
                }
            }

            let mut join_set = tokio::task::JoinSet::new();
            for pod_name in batch_candidates {
                let client = Arc::clone(&self.client);
                let ns = namespace.to_string();
                let new_pod = json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": pod_name,
                        "namespace": ns,
                        "labels": template_labels.clone(),
                        "ownerReferences": [{
                            "apiVersion": "v1",
                            "kind": "ReplicationController",
                            "name": name,
                            "uid": uid,
                            "controller": true,
                            "blockOwnerDeletion": true
                        }]
                    },
                    "spec": template_spec.clone(),
                    "status": {
                        "phase": "Pending"
                    }
                });
                join_set.spawn(async move {
                    let res = client.create_pod(&ns, new_pod).await;
                    (pod_name, res)
                });
            }

            let batch_failed = Self::collect_batch_results(
                &mut join_set,
                &mut created,
                &mut newly_created_pod_names,
                &mut create_error,
            )
            .await;

            if batch_failed {
                break;
            }
        }

        if self.is_rc_missing_or_terminating(namespace, name).await
            && !newly_created_pod_names.is_empty()
        {
            self.disown_created_pods(namespace, name, &newly_created_pod_names)
                .await;
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

    async fn sync_rc_pods(
        &self,
        namespace: &str,
        cfg: &RcConfig<'_>,
        owned_pods: Vec<Value>,
    ) -> Result<(Vec<Value>, Option<String>), ControllerError> {
        let current_count = owned_pods.len();
        let mut create_error = None;
        if !cfg.deleting {
            if current_count < cfg.desired_replicas {
                create_error = self
                    .scale_up_pods(
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

        let updated_pods =
            if (current_count == cfg.desired_replicas && create_error.is_none()) || cfg.deleting {
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
                    cfg.selector.as_ref(),
                )
                .await?
            };

        Ok((updated_pods, create_error))
    }

    /// Reconciles a single `ReplicationController` by adopting/releasing and scaling child Pods.
    pub async fn reconcile_rc(
        &self,
        namespace: &str,
        rc: &Value,
    ) -> Result<Value, ControllerError> {
        if rc.pointer("/metadata/deletionTimestamp").is_some() {
            return Ok(rc.clone());
        }

        let cfg = parse_rc_config(rc)?;

        let initial_pods = adopt_and_release_pods(
            &self.client,
            namespace,
            "v1",
            "ReplicationController",
            cfg.name,
            cfg.uid,
            cfg.deleting,
            cfg.selector.as_ref(),
        )
        .await?;

        let (updated_owned_pods, creation_error) =
            self.sync_rc_pods(namespace, &cfg, initial_pods).await?;
        let (actual_replicas, fully_labeled_replicas, ready_replicas) =
            compute_rc_metrics(&updated_owned_pods, &cfg.template);
        let observed_gen = rc
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(1)
            .max(1);

        let mut updated_rc = rc.clone();
        if cfg.selector_defaulted
            && !cfg.deleting
            && let Some(ref sel) = cfg.selector
            && let Some(spec) = updated_rc.get_mut("spec").and_then(Value::as_object_mut)
        {
            spec.insert("selector".to_string(), sel.clone());
        }
        let metrics = RcStatusMetrics {
            actual_replicas,
            fully_labeled_replicas,
            ready_replicas,
            available_replicas: ready_replicas,
            observed_gen,
        };
        apply_rc_status(&mut updated_rc, &metrics, creation_error.as_deref());

        if updated_rc == *rc {
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

fn compute_rc_metrics(pods: &[Value], template: &Value) -> (usize, usize, usize) {
    let actual = pods.len();
    let ready = pods.iter().filter(|p| super::is_pod_ready(p)).count();
    let tpl_labels = template
        .pointer("/metadata/labels")
        .and_then(Value::as_object);
    let fully_labeled = pods
        .iter()
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
        .count();
    (actual, fully_labeled, ready)
}

struct RcConfig<'a> {
    name: &'a str,
    uid: &'a str,
    deleting: bool,
    desired_replicas: usize,
    selector: Option<Value>,
    template: Value,
    selector_defaulted: bool,
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
    let template = rc
        .get("spec")
        .and_then(|s| s.get("template"))
        .cloned()
        .unwrap_or_else(|| json!({ "spec": { "containers": [] } }));
    let (selector, selector_defaulted) = match rc.pointer("/spec/selector") {
        Some(s) if s.is_object() && !s.as_object().unwrap().is_empty() => (Some(s.clone()), false),
        _ => (template.pointer("/metadata/labels").cloned(), true),
    };
    Ok(RcConfig {
        name,
        uid,
        deleting,
        desired_replicas,
        selector,
        template,
        selector_defaulted,
    })
}

struct RcStatusMetrics {
    actual_replicas: usize,
    fully_labeled_replicas: usize,
    ready_replicas: usize,
    available_replicas: usize,
    observed_gen: i64,
}

fn apply_rc_status(
    updated_rc: &mut Value,
    metrics: &RcStatusMetrics,
    creation_error: Option<&str>,
) {
    if let Some(status) = updated_rc.get_mut("status").and_then(Value::as_object_mut) {
        status.insert("replicas".to_string(), json!(metrics.actual_replicas));
        status.insert(
            "fullyLabeledReplicas".to_string(),
            json!(metrics.fully_labeled_replicas),
        );
        status.insert("readyReplicas".to_string(), json!(metrics.ready_replicas));
        status.insert(
            "availableReplicas".to_string(),
            json!(metrics.available_replicas),
        );
        status.insert(
            "observedGeneration".to_string(),
            json!(metrics.observed_gen),
        );
        update_status_conditions(status, creation_error);
    } else if let Some(rc_obj) = updated_rc.as_object_mut() {
        let mut status_map = Map::new();
        status_map.insert("replicas".to_string(), json!(metrics.actual_replicas));
        status_map.insert(
            "fullyLabeledReplicas".to_string(),
            json!(metrics.fully_labeled_replicas),
        );
        status_map.insert("readyReplicas".to_string(), json!(metrics.ready_replicas));
        status_map.insert(
            "availableReplicas".to_string(),
            json!(metrics.available_replicas),
        );
        status_map.insert(
            "observedGeneration".to_string(),
            json!(metrics.observed_gen),
        );
        update_status_conditions(&mut status_map, creation_error);
        rc_obj.insert("status".to_string(), Value::Object(status_map));
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

fn is_matching_rc_owner(o: &Value, rc_name: &str) -> bool {
    let matches_kind = o.get("kind").and_then(Value::as_str) == Some("ReplicationController");
    let matches_name = o.get("name").and_then(Value::as_str) == Some(rc_name);
    matches_kind && matches_name
}
