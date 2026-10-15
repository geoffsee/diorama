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

    async fn adopt_and_release_replicasets(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        deleting: bool,
        selector: &Value,
    ) -> Result<Vec<Value>, ControllerError> {
        let rs_list = self.client.list_replicasets(namespace).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "replicasets".to_string(),
                reason: e.to_string(),
            }
        })?;

        let all_rs = rs_list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let enforce_selector = super::has_label_selector(Some(selector));
        let mut owned = Vec::new();

        for mut rs in all_rs {
            let not_terminating = rs
                .pointer("/metadata/deletionTimestamp")
                .and_then(Value::as_str)
                .is_none();
            if !not_terminating {
                continue;
            }
            let Some(rs_name) = rs
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                continue;
            };

            let rs_labels = rs.pointer("/metadata/labels");
            let label_matches =
                !enforce_selector || super::matches_label_selector(selector, rs_labels);

            let owners = rs
                .pointer("/metadata/ownerReferences")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            let is_owned_by_us = owners.iter().any(|o| {
                o.get("kind").and_then(Value::as_str) == Some("Deployment")
                    && (o.get("uid").and_then(Value::as_str) == Some(uid)
                        || o.get("name").and_then(Value::as_str) == Some(name))
            });

            let has_any_controller = owners.iter().any(|o| {
                o.get("controller")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            });

            if is_owned_by_us {
                if enforce_selector && !label_matches {
                    Self::strip_deployment_owner(&mut rs, name, uid);
                    let _ = self.client.update_replicaset(namespace, &rs_name, rs).await;
                } else {
                    owned.push(rs);
                }
            } else if !deleting && !has_any_controller && enforce_selector && label_matches {
                let mut new_owners = owners;
                new_owners.push(json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": name,
                    "uid": uid,
                    "controller": true,
                    "blockOwnerDeletion": true
                }));
                if let Some(meta) = rs.get_mut("metadata").and_then(Value::as_object_mut) {
                    meta.insert("ownerReferences".to_string(), Value::Array(new_owners));
                }
                if let Ok(updated) = self
                    .client
                    .update_replicaset(namespace, &rs_name, rs.clone())
                    .await
                {
                    owned.push(updated);
                } else {
                    owned.push(rs);
                }
            }
        }

        Ok(owned)
    }

    fn strip_deployment_owner(rs: &mut Value, name: &str, uid: &str) {
        if let Some(owners) = rs
            .pointer_mut("/metadata/ownerReferences")
            .and_then(Value::as_array_mut)
        {
            owners.retain(|o| {
                let matches_kind = o.get("kind").and_then(Value::as_str) == Some("Deployment");
                let matches_uid = o.get("uid").and_then(Value::as_str) == Some(uid);
                let matches_name = o.get("name").and_then(Value::as_str) == Some(name);
                !(matches_kind && (matches_uid || matches_name))
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn sync_child_replicaset(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        deleting: bool,
        paused: bool,
        desired_replicas: i64,
        selector: Value,
        template: Value,
    ) -> Result<String, ControllerError> {
        let owned_rs = self
            .adopt_and_release_replicasets(namespace, name, uid, deleting, &selector)
            .await?;

        let default_rs_name = format!("{name}-rs");
        if deleting || paused {
            let active_name = owned_rs
                .first()
                .and_then(|rs| rs.pointer("/metadata/name").and_then(Value::as_str))
                .unwrap_or(&default_rs_name)
                .to_string();
            return Ok(active_name);
        }

        let prep = prepare_replicaset_template_and_selector(&template, &selector);
        let rs_template = prep.template;
        let rs_selector = prep.selector;
        let rs_labels = prep.labels;

        let existing_rs = if let Some(first) = owned_rs.into_iter().next() {
            Some(first)
        } else {
            self.client
                .get_replicaset(namespace, &default_rs_name)
                .await
                .ok()
        };

        let Some(mut rs) = existing_rs else {
            return self
                .create_child_replicaset(
                    namespace,
                    name,
                    uid,
                    &default_rs_name,
                    rs_labels,
                    rs_selector,
                    rs_template,
                    desired_replicas,
                )
                .await;
        };

        let rs_name = rs
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or(&default_rs_name)
            .to_string();
        let current_replicas = rs
            .get("spec")
            .and_then(|s| s.get("replicas"))
            .and_then(Value::as_i64)
            .unwrap_or(1);
        let existing_tpl = rs.pointer("/spec/template");
        let template_changed =
            existing_tpl != Some(&rs_template) && existing_tpl != Some(&template);
        let labels_missing = rs
            .pointer("/metadata/labels/pod-template-hash")
            .and_then(Value::as_str)
            .is_none();

        if current_replicas != desired_replicas || template_changed || labels_missing {
            update_replicaset_metadata_and_spec(
                &mut rs,
                rs_labels,
                rs_selector,
                rs_template.clone(),
                desired_replicas,
                template_changed,
            );
            self.client
                .update_replicaset(namespace, &rs_name, rs)
                .await
                .map_err(|e| ControllerError::ReconciliationFailed {
                    resource: format!("replicasets/{rs_name}"),
                    reason: e.to_string(),
                })?;

            if template_changed {
                self.recreate_pods_for_template_change(namespace, &rs_name, name)
                    .await;
            }
        }
        Ok(rs_name)
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_child_replicaset(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        default_rs_name: &str,
        rs_labels: Value,
        rs_selector: Value,
        rs_template: Value,
        desired_replicas: i64,
    ) -> Result<String, ControllerError> {
        let new_rs = json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": {
                "name": default_rs_name,
                "namespace": namespace,
                "labels": rs_labels,
                "annotations": {
                    "deployment.kubernetes.io/revision": "1"
                },
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
                "selector": rs_selector,
                "template": rs_template
            }
        });

        self.client
            .create_replicaset(namespace, new_rs)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("replicasets/{default_rs_name}"),
                reason: e.to_string(),
            })?;
        Ok(default_rs_name.to_string())
    }

    async fn recreate_pods_for_template_change(
        &self,
        namespace: &str,
        child_rs_name: &str,
        dep_name: &str,
    ) {
        let Ok(pod_list) = self.client.list_pods(namespace).await else {
            return;
        };
        let Some(items) = pod_list.get("items").and_then(Value::as_array) else {
            return;
        };
        for pod in items {
            if is_pod_owned_by_workload(pod, child_rs_name, dep_name)
                && let Some(pod_name) = pod.pointer("/metadata/name").and_then(Value::as_str)
            {
                let _ = self.client.delete_pod(namespace, pod_name).await;
            }
        }
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

        let deleting = deployment
            .pointer("/metadata/deletionTimestamp")
            .and_then(Value::as_str)
            .is_some();

        let paused = deployment
            .pointer("/spec/paused")
            .and_then(Value::as_bool)
            .unwrap_or(false);

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

        let child_rs_name = self
            .sync_child_replicaset(
                namespace,
                name,
                uid,
                deleting,
                paused,
                desired_replicas,
                selector,
                template,
            )
            .await?;

        if paused
            && self
                .client
                .get_replicaset(namespace, &child_rs_name)
                .await
                .is_err()
        {
            return Ok(deployment.clone());
        }

        let (raw_ready, raw_available) = self
            .resolve_replicas_status(namespace, &child_rs_name, name)
            .await;

        let ready_replicas = raw_ready.min(desired_replicas);
        let available_replicas = raw_available.min(desired_replicas);
        let observed_generation = deployment
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(1);

        let mut updated_deployment = deployment.clone();
        apply_deployment_status(
            &mut updated_deployment,
            &child_rs_name,
            desired_replicas,
            ready_replicas,
            available_replicas,
            observed_generation,
        );

        if updated_deployment.get("status") == deployment.get("status")
            && updated_deployment.pointer("/metadata/annotations")
                == deployment.pointer("/metadata/annotations")
        {
            return Ok(updated_deployment);
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

struct PreparedReplicaSetSpec {
    template: Value,
    selector: Value,
    labels: Value,
}

fn prepare_replicaset_template_and_selector(
    template: &Value,
    selector: &Value,
) -> PreparedReplicaSetSpec {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    template.to_string().hash(&mut hasher);
    let pod_template_hash = format!("{:x}", hasher.finish() & 0xffff_ffff);

    let mut rs_template = template.clone();
    if let Some(tpl_meta) = rs_template.as_object_mut().and_then(|o| {
        o.entry("metadata".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
    }) {
        let tpl_labels = tpl_meta
            .entry("labels".to_string())
            .or_insert_with(|| json!({}));
        if let Some(lbls) = tpl_labels.as_object_mut() {
            lbls.entry("pod-template-hash".to_string())
                .or_insert_with(|| json!(pod_template_hash));
        }
    }

    let mut rs_selector = selector.clone();
    if let Some(sel_obj) = rs_selector.as_object_mut() {
        let match_labels = sel_obj
            .entry("matchLabels".to_string())
            .or_insert_with(|| json!({}));
        if let Some(ml) = match_labels.as_object_mut() {
            ml.insert("pod-template-hash".to_string(), json!(pod_template_hash));
        }
    }

    let mut rs_labels = rs_selector
        .get("matchLabels")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let (Some(dst), Some(src)) = (
        rs_labels.as_object_mut(),
        rs_template
            .pointer("/metadata/labels")
            .and_then(Value::as_object),
    ) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }

    PreparedReplicaSetSpec {
        template: rs_template,
        selector: rs_selector,
        labels: rs_labels,
    }
}

fn update_replicaset_metadata_and_spec(
    rs: &mut Value,
    rs_labels: Value,
    rs_selector: Value,
    rs_template: Value,
    desired_replicas: i64,
    template_changed: bool,
) {
    if let Some(meta) = rs.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.insert("labels".to_string(), rs_labels);
        let annotations = meta
            .entry("annotations".to_string())
            .or_insert_with(|| json!({}));
        if let Some(ann_obj) = annotations.as_object_mut() {
            let next_rev = if template_changed { "2" } else { "1" };
            ann_obj.insert(
                "deployment.kubernetes.io/revision".to_string(),
                json!(next_rev),
            );
        }
    }
    if let Some(spec) = rs.get_mut("spec").and_then(Value::as_object_mut) {
        spec.insert("replicas".to_string(), json!(desired_replicas));
        spec.insert("selector".to_string(), rs_selector);
        spec.insert("template".to_string(), rs_template);
    }
}

fn apply_deployment_status(
    deployment: &mut Value,
    child_rs_name: &str,
    desired_replicas: i64,
    ready_replicas: i64,
    available_replicas: i64,
    observed_generation: i64,
) {
    let conditions = json!([
        {
            "type": "Available",
            "status": if available_replicas >= desired_replicas { "True" } else { "False" },
            "reason": "MinimumReplicasAvailable",
            "message": "Deployment has minimum availability."
        },
        {
            "type": "Progressing",
            "status": "True",
            "reason": "NewReplicaSetAvailable",
            "message": format!("ReplicaSet \"{child_rs_name}\" has successfully progressed.")
        }
    ]);

    if let Some(meta) = deployment
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
    {
        let annotations = meta
            .entry("annotations".to_string())
            .or_insert_with(|| json!({}));
        if let Some(ann_obj) = annotations.as_object_mut() {
            ann_obj
                .entry("deployment.kubernetes.io/revision".to_string())
                .or_insert_with(|| json!("1"));
        }
    }
    if let Some(status) = deployment.get_mut("status").and_then(Value::as_object_mut) {
        status.insert("replicas".to_string(), json!(desired_replicas));
        status.insert("readyReplicas".to_string(), json!(ready_replicas));
        status.insert("availableReplicas".to_string(), json!(available_replicas));
        status.insert("updatedReplicas".to_string(), json!(desired_replicas));
        status.insert("observedGeneration".to_string(), json!(observed_generation));
        status.insert("conditions".to_string(), conditions);
    } else if let Some(dep_obj) = deployment.as_object_mut() {
        dep_obj.insert(
            "status".to_string(),
            json!({
                "replicas": desired_replicas,
                "readyReplicas": ready_replicas,
                "availableReplicas": available_replicas,
                "updatedReplicas": desired_replicas,
                "observedGeneration": observed_generation,
                "conditions": conditions
            }),
        );
    }
}
