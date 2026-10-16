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
        cfg: &StatefulSetConfig<'_>,
        has_nodes: bool,
    ) -> Result<(), ControllerError> {
        for idx in 0..cfg.desired_replicas {
            let pod_name = format!("{}-{idx}", cfg.name);
            if let Ok(existing_pod) = self.client.get_pod(namespace, &pod_name).await {
                if existing_pod
                    .pointer("/status/phase")
                    .and_then(Value::as_str)
                    == Some("Failed")
                {
                    let _ = self.client.delete_pod(namespace, &pod_name).await;
                } else if cfg.ordered_ready
                    && (has_nodes || existing_pod.pointer("/status/conditions").is_some())
                    && !super::replicaset::is_pod_ready(&existing_pod)
                {
                    break;
                } else {
                    continue;
                }
            }

            self.ensure_ordinal_pvcs(namespace, cfg, idx).await?;

            let new_pod = build_ordinal_pod(namespace, cfg, idx, &pod_name);
            self.client
                .create_pod(namespace, new_pod)
                .await
                .map_err(|e| ControllerError::ReconciliationFailed {
                    resource: format!("pods/{pod_name}"),
                    reason: e.to_string(),
                })?;

            if cfg.ordered_ready && has_nodes {
                break;
            }
        }
        Ok(())
    }

    async fn ensure_ordinal_pvcs(
        &self,
        namespace: &str,
        cfg: &StatefulSetConfig<'_>,
        idx: usize,
    ) -> Result<(), ControllerError> {
        for vct in &cfg.volume_claim_templates {
            let vct_name = vct
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("data");
            let pvc_name = format!("{vct_name}-{}-{idx}", cfg.name);
            if self.client.get_pvc(namespace, &pvc_name).await.is_ok() {
                continue;
            }
            let mut pvc_owner_refs = Vec::new();
            if cfg.pvc_retention_when_deleted == "Delete" {
                pvc_owner_refs.push(json!({
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "name": cfg.name,
                    "uid": cfg.uid,
                    "controller": false,
                    "blockOwnerDeletion": true
                }));
            }
            let pvc_labels = vct
                .pointer("/metadata/labels")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let pvc_spec = vct.get("spec").cloned().unwrap_or_else(|| json!({}));

            let new_pvc = json!({
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": {
                    "name": pvc_name,
                    "namespace": namespace,
                    "labels": pvc_labels,
                    "ownerReferences": pvc_owner_refs
                },
                "spec": pvc_spec
            });
            let _ = self.client.create_pvc(namespace, new_pvc).await;
        }
        Ok(())
    }

    async fn prune_excess_ordinal_pods(
        &self,
        namespace: &str,
        cfg: &StatefulSetConfig<'_>,
        has_nodes: bool,
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

        if cfg.ordered_ready {
            for idx in 0..cfg.desired_replicas {
                let pname = format!("{}-{idx}", cfg.name);
                if let Some(pod) = all_pods
                    .iter()
                    .find(|p| p.pointer("/metadata/name").and_then(Value::as_str) == Some(&pname))
                    && (has_nodes || pod.pointer("/status/conditions").is_some())
                    && !super::replicaset::is_pod_ready(pod)
                {
                    return Ok(());
                }
            }
        }

        let mut to_delete: Vec<(usize, String)> = Vec::new();
        for pod in all_pods {
            let is_owned = pod
                .get("metadata")
                .and_then(|m| m.get("ownerReferences"))
                .and_then(Value::as_array)
                .is_some_and(|owners| {
                    owners.iter().any(|o| {
                        o.get("kind").and_then(Value::as_str) == Some("StatefulSet")
                            && (o.get("uid").and_then(Value::as_str) == Some(cfg.uid)
                                || o.get("name").and_then(Value::as_str) == Some(cfg.name))
                    })
                });

            if !is_owned {
                continue;
            }

            if cfg.ordered_ready {
                if pod
                    .pointer("/metadata/deletionTimestamp")
                    .and_then(Value::as_str)
                    .is_some()
                {
                    return Ok(());
                }
                if (has_nodes || pod.pointer("/status/conditions").is_some())
                    && !super::replicaset::is_pod_ready(&pod)
                {
                    return Ok(());
                }
            }

            if let Some(pname) = pod
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
                && let Some(suffix) = pname.strip_prefix(&format!("{}-", cfg.name))
                && let Ok(idx) = suffix.parse::<usize>()
                && idx >= cfg.desired_replicas
            {
                to_delete.push((idx, pname.to_string()));
            }
        }

        if cfg.pvc_retention_when_scaled == "Delete" {
            for &(idx, _) in &to_delete {
                for vct in &cfg.volume_claim_templates {
                    let vct_name = vct
                        .pointer("/metadata/name")
                        .and_then(Value::as_str)
                        .unwrap_or("data");
                    let pvc_name = format!("{vct_name}-{}-{idx}", cfg.name);
                    let _ = self.client.delete_pvc(namespace, &pvc_name).await;
                }
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
            if cfg.ordered_ready && has_nodes {
                break;
            }
        }
        Ok(())
    }

    async fn rolling_update_ordinal_pods(
        &self,
        namespace: &str,
        cfg: &StatefulSetConfig<'_>,
        has_nodes: bool,
    ) {
        for idx in (0..cfg.desired_replicas).rev() {
            let pname = format!("{}-{idx}", cfg.name);
            let Ok(pod) = self.client.get_pod(namespace, &pname).await else {
                return;
            };
            if cfg.ordered_ready
                && (has_nodes || pod.pointer("/status/conditions").is_some())
                && !super::replicaset::is_pod_ready(&pod)
            {
                return;
            }
        }

        for idx in (cfg.partition.min(cfg.desired_replicas)..cfg.desired_replicas).rev() {
            let pname = format!("{}-{idx}", cfg.name);
            let Ok(pod) = self.client.get_pod(namespace, &pname).await else {
                continue;
            };
            let pod_rev = pod
                .pointer("/metadata/labels/controller-revision-hash")
                .and_then(Value::as_str);
            if pod_rev != Some(&cfg.update_revision) {
                let _ = self.client.delete_pod(namespace, &pname).await;
                if cfg.ordered_ready && has_nodes {
                    break;
                }
            }
        }
    }

    /// Reconciles a single `StatefulSet` by maintaining ordered ordinal pods (name-0, name-1, etc.).
    pub async fn reconcile_statefulset(
        &self,
        namespace: &str,
        ss: &Value,
    ) -> Result<Value, ControllerError> {
        let cfg = parse_statefulset_config(ss)?;
        let has_nodes = self
            .client
            .list_nodes()
            .await
            .ok()
            .and_then(|n| n.get("items").and_then(Value::as_array).cloned())
            .is_some_and(|items| !items.is_empty());

        let _ = super::adopt_and_release_pods(
            &self.client,
            namespace,
            "apps/v1",
            "StatefulSet",
            cfg.name,
            cfg.uid,
            cfg.deleting,
            ss.pointer("/spec/selector"),
        )
        .await?;

        if !cfg.deleting {
            self.ensure_ordinal_pods(namespace, &cfg, has_nodes).await?;
            self.prune_excess_ordinal_pods(namespace, &cfg, has_nodes)
                .await?;

            if cfg.update_strategy_type == "RollingUpdate" {
                self.rolling_update_ordinal_pods(namespace, &cfg, has_nodes)
                    .await;
            }
        }

        let counts = self
            .count_pod_status(
                namespace,
                cfg.name,
                cfg.desired_replicas,
                &cfg.update_revision,
                ss,
            )
            .await;
        let observed_generation = ss
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(1);

        let mut updated_ss = ss.clone();
        apply_statefulset_status(
            &mut updated_ss,
            &counts,
            &cfg.update_revision,
            observed_generation,
        );

        if updated_ss.get("status") == ss.get("status") {
            return Ok(updated_ss);
        }

        self.client
            .update_statefulset(namespace, cfg.name, updated_ss)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("statefulsets/{}", cfg.name),
                reason: e.to_string(),
            })
    }

    async fn count_pod_status(
        &self,
        namespace: &str,
        name: &str,
        desired_replicas: usize,
        update_revision: &str,
        ss: &Value,
    ) -> StatefulSetCounts {
        let mut existing_replicas = 0usize;
        let mut ready_count = 0usize;
        let mut updated_count = 0usize;
        let mut pod_revisions = Vec::new();
        for idx in 0..desired_replicas {
            let pname = format!("{name}-{idx}");
            let Ok(pod) = self.client.get_pod(namespace, &pname).await else {
                continue;
            };
            if pod
                .pointer("/metadata/deletionTimestamp")
                .and_then(Value::as_str)
                .is_some()
            {
                continue;
            }
            existing_replicas += 1;
            if super::replicaset::is_pod_ready(&pod) {
                ready_count += 1;
            }
            let pod_rev = pod
                .pointer("/metadata/labels/controller-revision-hash")
                .and_then(Value::as_str)
                .unwrap_or(update_revision)
                .to_string();
            if pod_rev == update_revision {
                updated_count += 1;
            }
            pod_revisions.push(pod_rev);
        }

        let current_revision = if updated_count == existing_replicas && existing_replicas > 0 {
            update_revision.to_string()
        } else if let Some(first_rev) = pod_revisions.first() {
            first_rev.clone()
        } else {
            ss.pointer("/status/currentRevision")
                .and_then(Value::as_str)
                .unwrap_or(update_revision)
                .to_string()
        };
        let current_replicas = pod_revisions
            .iter()
            .filter(|rev| *rev == &current_revision)
            .count();

        StatefulSetCounts {
            existing: existing_replicas,
            ready: ready_count,
            updated: updated_count,
            current: current_replicas,
            current_revision,
        }
    }
}

struct StatefulSetCounts {
    existing: usize,
    ready: usize,
    updated: usize,
    current: usize,
    current_revision: String,
}

fn apply_statefulset_status(
    updated_ss: &mut Value,
    counts: &StatefulSetCounts,
    update_revision: &str,
    observed_generation: i64,
) {
    if let Some(status) = updated_ss.get_mut("status").and_then(Value::as_object_mut) {
        status.insert("replicas".to_string(), json!(counts.existing));
        status.insert("currentReplicas".to_string(), json!(counts.current));
        status.insert("updatedReplicas".to_string(), json!(counts.updated));
        status.insert("readyReplicas".to_string(), json!(counts.ready));
        status.insert("availableReplicas".to_string(), json!(counts.ready));
        status.insert(
            "currentRevision".to_string(),
            json!(counts.current_revision),
        );
        status.insert("updateRevision".to_string(), json!(update_revision));
        status.insert("observedGeneration".to_string(), json!(observed_generation));
    } else if let Some(ss_obj) = updated_ss.as_object_mut() {
        ss_obj.insert(
            "status".to_string(),
            json!({
                "replicas": counts.existing,
                "currentReplicas": counts.current,
                "updatedReplicas": counts.updated,
                "readyReplicas": counts.ready,
                "availableReplicas": counts.ready,
                "currentRevision": counts.current_revision,
                "updateRevision": update_revision,
                "observedGeneration": observed_generation
            }),
        );
    }
}

fn compute_template_revision(name: &str, template: &Value) -> String {
    let serialized = serde_json::to_string(template).unwrap_or_default();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in serialized.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{name}-{:010x}", hash & 0x00ff_ffff_ffff)
}

struct StatefulSetConfig<'a> {
    name: &'a str,
    uid: &'a str,
    deleting: bool,
    desired_replicas: usize,
    ordered_ready: bool,
    update_strategy_type: &'a str,
    partition: usize,
    update_revision: String,
    template_labels: Value,
    template_spec: Value,
    volume_claim_templates: Vec<Value>,
    pvc_retention_when_deleted: &'a str,
    pvc_retention_when_scaled: &'a str,
}

fn parse_statefulset_config(ss: &Value) -> Result<StatefulSetConfig<'_>, ControllerError> {
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

    let deleting = ss
        .pointer("/metadata/deletionTimestamp")
        .and_then(Value::as_str)
        .is_some();

    let desired_replicas = ss
        .get("spec")
        .and_then(|s| s.get("replicas"))
        .and_then(Value::as_i64)
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(1);

    let ordered_ready = ss
        .pointer("/spec/podManagementPolicy")
        .and_then(Value::as_str)
        != Some("Parallel");

    let update_strategy_type = ss
        .pointer("/spec/updateStrategy/type")
        .and_then(Value::as_str)
        .unwrap_or("RollingUpdate");

    let partition = ss
        .pointer("/spec/updateStrategy/rollingUpdate/partition")
        .and_then(Value::as_i64)
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(0);

    let template = ss
        .get("spec")
        .and_then(|s| s.get("template"))
        .cloned()
        .unwrap_or_else(|| json!({ "spec": { "containers": [] } }));

    let update_revision = compute_template_revision(name, &template);

    let template_labels = template
        .get("metadata")
        .and_then(|m| m.get("labels"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    let template_spec = template
        .get("spec")
        .cloned()
        .unwrap_or_else(|| json!({ "containers": [] }));

    let volume_claim_templates = ss
        .pointer("/spec/volumeClaimTemplates")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let pvc_retention_when_deleted = ss
        .pointer("/spec/persistentVolumeClaimRetentionPolicy/whenDeleted")
        .and_then(Value::as_str)
        .unwrap_or("Retain");

    let pvc_retention_when_scaled = ss
        .pointer("/spec/persistentVolumeClaimRetentionPolicy/whenScaled")
        .and_then(Value::as_str)
        .unwrap_or("Retain");

    Ok(StatefulSetConfig {
        name,
        uid,
        deleting,
        desired_replicas,
        ordered_ready,
        update_strategy_type,
        partition,
        update_revision,
        template_labels,
        template_spec,
        volume_claim_templates,
        pvc_retention_when_deleted,
        pvc_retention_when_scaled,
    })
}

fn build_ordinal_pod(
    namespace: &str,
    cfg: &StatefulSetConfig<'_>,
    idx: usize,
    pod_name: &str,
) -> Value {
    let mut pod_labels = cfg.template_labels.clone();
    if let Some(labels_obj) = pod_labels.as_object_mut() {
        labels_obj.insert(
            "statefulset.kubernetes.io/pod-name".to_string(),
            json!(pod_name),
        );
        labels_obj.insert(
            "apps.kubernetes.io/pod-index".to_string(),
            json!(idx.to_string()),
        );
        labels_obj.insert(
            "controller-revision-hash".to_string(),
            json!(cfg.update_revision),
        );
    }

    let mut pod_spec = cfg.template_spec.clone();
    attach_pvc_volumes(&mut pod_spec, cfg, idx);

    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": namespace,
            "labels": pod_labels,
            "ownerReferences": [{
                "apiVersion": "apps/v1",
                "kind": "StatefulSet",
                "name": cfg.name,
                "uid": cfg.uid,
                "controller": true,
                "blockOwnerDeletion": true
            }]
        },
        "spec": pod_spec,
        "status": {
            "phase": "Pending"
        }
    })
}

fn attach_pvc_volumes(pod_spec: &mut Value, cfg: &StatefulSetConfig<'_>, idx: usize) {
    if cfg.volume_claim_templates.is_empty() {
        return;
    }
    let Some(spec_obj) = pod_spec.as_object_mut() else {
        return;
    };
    let volumes = spec_obj
        .entry("volumes".to_string())
        .or_insert_with(|| json!([]));
    let Some(vol_arr) = volumes.as_array_mut() else {
        return;
    };
    for vct in &cfg.volume_claim_templates {
        let vct_name = vct
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("data");
        let pvc_name = format!("{vct_name}-{}-{idx}", cfg.name);
        let already_has = vol_arr
            .iter()
            .any(|v| v.get("name").and_then(Value::as_str) == Some(vct_name));
        if !already_has {
            vol_arr.push(json!({
                "name": vct_name,
                "persistentVolumeClaim": {
                    "claimName": pvc_name
                }
            }));
        }
    }
}
