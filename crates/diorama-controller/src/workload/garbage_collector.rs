use std::sync::Arc;

use diorama_apiserver::client::KubernetesApiClient;
use serde_json::Value;

use crate::error::ControllerError;

use diorama_apiserver::ApiserverError;

fn matches_uid(item: &Value, expected_uid: Option<&str>) -> bool {
    let Some(uid) = expected_uid else { return true };
    if uid.is_empty() {
        return true;
    }
    item.get("metadata")
        .and_then(|m| m.get("uid"))
        .and_then(Value::as_str)
        == Some(uid)
}

fn has_foreground_deletion(item: &Value) -> bool {
    let has_del_ts = item
        .pointer("/metadata/deletionTimestamp")
        .and_then(Value::as_str)
        .is_some();
    let has_fg_finalizer = item
        .pointer("/metadata/finalizers")
        .and_then(Value::as_array)
        .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("foregroundDeletion")));
    has_del_ts && has_fg_finalizer
}

fn has_orphan_deletion(item: &Value) -> bool {
    let has_del_ts = item
        .pointer("/metadata/deletionTimestamp")
        .and_then(Value::as_str)
        .is_some();
    has_del_ts && has_orphan_finalizer(item)
}

fn has_orphan_finalizer(item: &Value) -> bool {
    item.pointer("/metadata/finalizers")
        .and_then(Value::as_array)
        .is_some_and(|arr| {
            arr.iter().any(|v| {
                matches!(
                    v.as_str(),
                    Some("orphan" | "orphanDependents" | "kubernetes.io/orphan")
                )
            })
        })
}

fn blocks_owner_deletion(owner_ref: &Value) -> bool {
    if let Some(block) = owner_ref.get("blockOwnerDeletion").and_then(Value::as_bool) {
        return block;
    }
    owner_ref
        .get("controller")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn owner_present(res: Result<Value, ApiserverError>, expected_uid: Option<&str>) -> bool {
    match res {
        Ok(owner) => matches_uid(&owner, expected_uid) && !has_foreground_deletion(&owner),
        Err(ApiserverError::NotFound { .. }) => false,
        Err(_) => true, // Transient/permission error: assume owner present to prevent eager deletion
    }
}

#[derive(Clone, Debug)]
pub struct GarbageCollector {
    client: Arc<KubernetesApiClient>,
}

impl GarbageCollector {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    /// Reconciles garbage collection in the specified namespace, removing eligible dependents
    /// whose `ownerReferences` point to non-existent parents. Runs recursively until cascading deletes converge.
    pub async fn reconcile(&self, namespace: &str) -> Result<usize, ControllerError> {
        let mut total_deleted = 0;
        let mut iterations = 0;

        total_deleted += self.reconcile_namespace_termination(namespace).await?;

        loop {
            if iterations > 100 {
                return Err(ControllerError::ReconciliationFailed {
                    resource: format!("garbage collection in namespace '{namespace}'"),
                    reason: "cascading deletion did not converge within 100 passes".to_string(),
                });
            }
            iterations += 1;
            let pass_deleted = self.reconcile_pass(namespace).await?;
            if pass_deleted == 0 {
                break;
            }
            total_deleted += pass_deleted;
        }

        let _ = self.finalize_terminating_namespace(namespace).await;

        Ok(total_deleted)
    }

    async fn reconcile_pass(&self, namespace: &str) -> Result<usize, ControllerError> {
        let orphan_count = self.reconcile_orphan_owners(namespace).await;
        let rs_count = self.reconcile_replicasets(namespace).await;
        let job_count = self.reconcile_jobs(namespace).await;
        let pod_count = self.reconcile_pods(namespace).await;
        let slice_count = self.reconcile_endpointslices(namespace).await;
        let endpoint_count = self.reconcile_endpoints(namespace).await;
        let cr_count = self.reconcile_custom_resources(namespace).await;
        let fg_count = self.reconcile_foreground_owners(namespace).await;
        Ok(rs_count
            + job_count
            + pod_count
            + slice_count
            + endpoint_count
            + cr_count
            + fg_count
            + orphan_count)
    }

    async fn reconcile_foreground_owners(&self, namespace: &str) -> usize {
        let pods = self
            .client
            .list_pods(namespace)
            .await
            .ok()
            .and_then(|l| l.get("items").and_then(Value::as_array).cloned())
            .unwrap_or_default();
        let rs_items = self
            .client
            .list_replicasets(namespace)
            .await
            .ok()
            .and_then(|l| l.get("items").and_then(Value::as_array).cloned())
            .unwrap_or_default();

        let mut dep_deployments = rs_items.clone();
        dep_deployments.extend(pods.iter().cloned());

        let mut finalized = 0;
        if let Ok(list) = self.client.list_deployments(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_foreground_owner(namespace, "Deployment", items, &dep_deployments)
                .await;
        }
        finalized += self
            .finalize_foreground_owner(namespace, "ReplicaSet", &rs_items, &pods)
            .await;
        if let Ok(list) = self.client.list_replicationcontrollers(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_foreground_owner(namespace, "ReplicationController", items, &pods)
                .await;
        }
        if let Ok(list) = self.client.list_jobs(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_foreground_owner(namespace, "Job", items, &pods)
                .await;
        }
        if let Ok(list) = self.client.list_statefulsets(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_foreground_owner(namespace, "StatefulSet", items, &pods)
                .await;
        }
        if let Ok(list) = self.client.list_daemonsets(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_foreground_owner(namespace, "DaemonSet", items, &pods)
                .await;
        }
        finalized
    }

    async fn finalize_foreground_owner(
        &self,
        namespace: &str,
        kind: &str,
        items: &[Value],
        dependents: &[Value],
    ) -> usize {
        let mut count = 0;
        for item in items {
            if !has_foreground_deletion(item) {
                continue;
            }
            let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
                continue;
            };
            let uid = item.pointer("/metadata/uid").and_then(Value::as_str);
            if self
                .has_blocking_dependent(namespace, dependents, kind, name, uid)
                .await
            {
                continue;
            }
            if self.strip_and_delete(namespace, kind, name, item).await {
                count += 1;
            }
        }
        count
    }

    async fn strip_and_delete(
        &self,
        namespace: &str,
        kind: &str,
        name: &str,
        item: &Value,
    ) -> bool {
        let mut cleaned = item.clone();
        Self::strip_deletion_metadata(&mut cleaned);
        match kind {
            "Deployment" => {
                let _ = self
                    .client
                    .update_deployment(namespace, name, cleaned)
                    .await;
                self.client.delete_deployment(namespace, name).await.is_ok()
            },
            "ReplicaSet" => {
                let _ = self
                    .client
                    .update_replicaset(namespace, name, cleaned)
                    .await;
                self.client.delete_replicaset(namespace, name).await.is_ok()
            },
            "ReplicationController" => {
                let _ = self
                    .client
                    .update_replicationcontroller(namespace, name, cleaned)
                    .await;
                self.client
                    .delete_replicationcontroller(namespace, name)
                    .await
                    .is_ok()
            },
            "Job" => {
                let _ = self.client.update_job(namespace, name, cleaned).await;
                self.client.delete_job(namespace, name).await.is_ok()
            },
            "StatefulSet" => {
                let _ = self
                    .client
                    .update_statefulset(namespace, name, cleaned)
                    .await;
                self.client
                    .delete_statefulset(namespace, name)
                    .await
                    .is_ok()
            },
            "DaemonSet" => {
                let _ = self.client.update_daemonset(namespace, name, cleaned).await;
                self.client.delete_daemonset(namespace, name).await.is_ok()
            },
            "CronJob" => {
                let _ = self.client.update_cronjob(namespace, name, cleaned).await;
                self.client.delete_cronjob(namespace, name).await.is_ok()
            },
            _ => {
                self.strip_and_delete_cr(namespace, kind, name, cleaned)
                    .await
            },
        }
    }

    async fn strip_and_delete_cr(
        &self,
        namespace: &str,
        kind: &str,
        name: &str,
        cleaned: Value,
    ) -> bool {
        if let Ok(crd_list) = self.client.list_crds().await
            && let Some(items) = crd_list.get("items").and_then(Value::as_array)
        {
            for crd in items {
                let crd_kind = crd.pointer("/spec/names/kind").and_then(Value::as_str);
                if crd_kind == Some(kind) {
                    let group = crd
                        .pointer("/spec/group")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let plural = crd
                        .pointer("/spec/names/plural")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let _ = self
                        .client
                        .update_custom_resource(group, plural, namespace, name, cleaned, None)
                        .await;
                    return self
                        .client
                        .delete_custom_resource(group, plural, namespace, name)
                        .await
                        .is_ok();
                }
            }
        }
        false
    }

    fn strip_deletion_metadata(obj: &mut Value) {
        if let Some(meta) = obj.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.remove("finalizers");
            meta.remove("deletionTimestamp");
        }
    }

    async fn has_blocking_dependent(
        &self,
        namespace: &str,
        dependents: &[Value],
        owner_kind: &str,
        owner_name: &str,
        owner_uid: Option<&str>,
    ) -> bool {
        for dep in dependents {
            let Some(owners) = dep
                .pointer("/metadata/ownerReferences")
                .and_then(Value::as_array)
            else {
                continue;
            };
            let matching_owner = owners.iter().find(|o| {
                o.get("kind").and_then(Value::as_str) == Some(owner_kind)
                    && (o.get("name").and_then(Value::as_str) == Some(owner_name)
                        || (owner_uid.is_some()
                            && o.get("uid").and_then(Value::as_str) == owner_uid))
            });
            let Some(owner_ref) = matching_owner else {
                continue;
            };

            // If blockOwnerDeletion is false, this reference does not block owner deletion
            if !blocks_owner_deletion(owner_ref) {
                continue;
            }

            // If the dependent is terminating or has no other valid live owner, it blocks foreground deletion
            if dep.pointer("/metadata/deletionTimestamp").is_some() {
                return true;
            }
            let mut has_other_live_owner = false;
            for o in owners {
                let Some(k) = o.get("kind").and_then(Value::as_str) else {
                    continue;
                };
                let Some(n) = o.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if k == owner_kind && n == owner_name {
                    continue;
                }
                let uid = o.get("uid").and_then(Value::as_str);
                if self.check_owner_exists(namespace, k, n, uid).await {
                    has_other_live_owner = true;
                    break;
                }
            }
            if !has_other_live_owner {
                return true;
            }
        }
        false
    }

    async fn reconcile_replicasets(&self, namespace: &str) -> usize {
        let Ok(rs_list) = self.client.list_replicasets(namespace).await else {
            return 0;
        };
        let Some(items) = rs_list.get("items").and_then(Value::as_array) else {
            return 0;
        };

        let mut deleted = 0;
        for mut rs in items.clone() {
            if !self
                .evaluate_and_prune_dependent(
                    namespace,
                    &mut rs,
                    "apps",
                    "ReplicaSet",
                    "replicasets",
                )
                .await
            {
                continue;
            }
            let Some(name) = rs
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            if self.client.delete_replicaset(namespace, name).await.is_ok() {
                deleted += 1;
            }
        }
        deleted
    }

    async fn reconcile_jobs(&self, namespace: &str) -> usize {
        let Ok(job_list) = self.client.list_jobs(namespace).await else {
            return 0;
        };
        let Some(items) = job_list.get("items").and_then(Value::as_array) else {
            return 0;
        };

        let mut deleted = 0;
        for mut job in items.clone() {
            if !self
                .evaluate_and_prune_dependent(namespace, &mut job, "batch", "Job", "jobs")
                .await
            {
                continue;
            }
            let Some(name) = job
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            if self.client.delete_job(namespace, name).await.is_ok() {
                deleted += 1;
            }
        }
        deleted
    }

    async fn reconcile_pods(&self, namespace: &str) -> usize {
        let Ok(pod_list) = self.client.list_pods(namespace).await else {
            return 0;
        };
        let Some(items) = pod_list.get("items").and_then(Value::as_array) else {
            return 0;
        };

        let mut deleted = 0;
        for mut pod in items.clone() {
            if !self
                .evaluate_and_prune_dependent(namespace, &mut pod, "", "Pod", "pods")
                .await
            {
                continue;
            }
            let Some(name) = pod
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };

            if self.client.delete_pod(namespace, name).await.is_ok() {
                deleted += 1;
            }
        }
        deleted
    }

    async fn reconcile_endpointslices(&self, namespace: &str) -> usize {
        let Ok(list) = self.client.list_endpointslices(namespace).await else {
            return 0;
        };
        let Some(items) = list.get("items").and_then(Value::as_array) else {
            return 0;
        };

        let mut deleted = 0;
        for mut item in items.clone() {
            if !self
                .evaluate_and_prune_dependent(
                    namespace,
                    &mut item,
                    "discovery.k8s.io",
                    "EndpointSlice",
                    "endpointslices",
                )
                .await
            {
                continue;
            }
            let Some(name) = item
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            if self
                .client
                .delete_endpointslice(namespace, name)
                .await
                .is_ok()
            {
                deleted += 1;
            }
        }
        deleted
    }

    async fn reconcile_endpoints(&self, namespace: &str) -> usize {
        let Ok(list) = self.client.list_endpoints(namespace).await else {
            return 0;
        };
        let Some(items) = list.get("items").and_then(Value::as_array) else {
            return 0;
        };

        let mut deleted = 0;
        for mut item in items.clone() {
            if !self
                .evaluate_and_prune_dependent(namespace, &mut item, "", "Endpoints", "endpoints")
                .await
            {
                continue;
            }
            let Some(name) = item
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            if self.client.delete_endpoints(namespace, name).await.is_ok() {
                deleted += 1;
            }
        }
        deleted
    }

    async fn get_owner_object(
        &self,
        namespace: &str,
        kind: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        match kind {
            "Deployment" => self.client.get_deployment(namespace, name).await,
            "ReplicaSet" => self.client.get_replicaset(namespace, name).await,
            "StatefulSet" => self.client.get_statefulset(namespace, name).await,
            "DaemonSet" => self.client.get_daemonset(namespace, name).await,
            "Job" => self.client.get_job(namespace, name).await,
            "CronJob" => self.client.get_cronjob(namespace, name).await,
            "Service" => self.client.get_service(namespace, name).await,
            "ReplicationController" => self.client.get_replicationcontroller(namespace, name).await,
            "Pod" => self.client.get_pod(namespace, name).await,
            "ConfigMap" => self.client.get_configmap(namespace, name).await,
            "Secret" => self.client.get_secret(namespace, name).await,
            "PersistentVolumeClaim" => self.client.get_pvc(namespace, name).await,
            "Lease" => self.client.get_lease(namespace, name).await,
            _ => self.get_crd_owner_object(namespace, kind, name).await,
        }
    }

    async fn get_crd_owner_object(
        &self,
        namespace: &str,
        kind: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        if let Ok(crd_list) = self.client.list_crds().await
            && let Some(items) = crd_list.get("items").and_then(Value::as_array)
        {
            for crd in items {
                let crd_kind = crd.pointer("/spec/names/kind").and_then(Value::as_str);
                if crd_kind == Some(kind) {
                    let group = crd
                        .pointer("/spec/group")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let plural = crd
                        .pointer("/spec/names/plural")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    return self
                        .client
                        .get_custom_resource(group, plural, namespace, name)
                        .await;
                }
            }
        }
        Err(ApiserverError::NotFound {
            resource: kind.to_string(),
            name: name.to_string(),
        })
    }

    async fn check_owner_exists(
        &self,
        namespace: &str,
        kind: &str,
        name: &str,
        expected_uid: Option<&str>,
    ) -> bool {
        owner_present(
            self.get_owner_object(namespace, kind, name).await,
            expected_uid,
        )
    }

    async fn partition_owner_references(
        &self,
        namespace: &str,
        owner_refs: &[Value],
    ) -> (Vec<Value>, Vec<Value>) {
        let mut valid_owners = Vec::new();
        let mut missing_owners = Vec::new();

        for owner in owner_refs {
            let Some(o_kind) = owner.get("kind").and_then(Value::as_str) else {
                continue;
            };
            let Some(o_name) = owner.get("name").and_then(Value::as_str) else {
                continue;
            };
            let expected_uid = owner.get("uid").and_then(Value::as_str);

            let res = self.get_owner_object(namespace, o_kind, o_name).await;
            if owner_present(res, expected_uid) {
                valid_owners.push(owner.clone());
            } else {
                missing_owners.push(owner.clone());
            }
        }

        (valid_owners, missing_owners)
    }

    async fn evaluate_and_prune_dependent(
        &self,
        namespace: &str,
        resource: &mut Value,
        group: &str,
        kind: &str,
        plural: &str,
    ) -> bool {
        if resource
            .get("metadata")
            .and_then(|m| m.get("deletionTimestamp"))
            .and_then(Value::as_str)
            .is_some()
        {
            return false;
        }

        if has_orphan_finalizer(resource) {
            return false;
        }

        let Some(owner_refs) = resource
            .get("metadata")
            .and_then(|m| m.get("ownerReferences"))
            .and_then(Value::as_array)
            .cloned()
        else {
            return false;
        };

        if owner_refs.is_empty() {
            return false;
        }

        let (valid_owners, missing_owners) = self
            .partition_owner_references(namespace, &owner_refs)
            .await;

        if !valid_owners.is_empty() {
            if !missing_owners.is_empty() {
                if let Some(meta) = resource.get_mut("metadata").and_then(Value::as_object_mut) {
                    meta.insert("ownerReferences".to_string(), Value::Array(valid_owners));
                }
                if let Some(name) = resource.pointer("/metadata/name").and_then(Value::as_str)
                    && !plural.is_empty()
                {
                    let _ = self
                        .client
                        .replace_namespaced_object(
                            group,
                            kind,
                            plural,
                            namespace,
                            name,
                            resource.clone(),
                        )
                        .await;
                }
            }
            return false;
        }

        valid_owners.is_empty() && !missing_owners.is_empty()
    }

    async fn reconcile_custom_resources(&self, namespace: &str) -> usize {
        let Ok(crd_list) = self.client.list_crds().await else {
            return 0;
        };
        let Some(crds) = crd_list.get("items").and_then(Value::as_array) else {
            return 0;
        };

        let mut deleted = 0;
        for crd in crds {
            let Some(group) = crd.pointer("/spec/group").and_then(Value::as_str) else {
                continue;
            };
            let Some(plural) = crd.pointer("/spec/names/plural").and_then(Value::as_str) else {
                continue;
            };
            let Ok(list) = self
                .client
                .list_custom_resources(group, plural, namespace)
                .await
            else {
                continue;
            };
            let Some(items) = list.get("items").and_then(Value::as_array) else {
                continue;
            };
            for mut item in items.clone() {
                if !self
                    .evaluate_and_prune_dependent(namespace, &mut item, group, "", plural)
                    .await
                {
                    continue;
                }
                let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
                    continue;
                };
                if self
                    .client
                    .delete_custom_resource(group, plural, namespace, name)
                    .await
                    .is_ok()
                {
                    deleted += 1;
                }
            }
        }
        deleted
    }

    async fn reconcile_orphan_owners(&self, namespace: &str) -> usize {
        let mut finalized = 0;
        if let Ok(list) = self.client.list_deployments(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_orphan_owners(namespace, "Deployment", items)
                .await;
        }
        if let Ok(list) = self.client.list_replicasets(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_orphan_owners(namespace, "ReplicaSet", items)
                .await;
        }
        if let Ok(list) = self.client.list_jobs(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self.finalize_orphan_owners(namespace, "Job", items).await;
        }
        if let Ok(list) = self.client.list_statefulsets(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_orphan_owners(namespace, "StatefulSet", items)
                .await;
        }
        if let Ok(list) = self.client.list_replicationcontrollers(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_orphan_owners(namespace, "ReplicationController", items)
                .await;
        }
        if let Ok(list) = self.client.list_daemonsets(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_orphan_owners(namespace, "DaemonSet", items)
                .await;
        }
        finalized
    }

    async fn finalize_orphan_owners(&self, namespace: &str, kind: &str, items: &[Value]) -> usize {
        let mut count = 0;
        for item in items {
            if !has_orphan_deletion(item) {
                continue;
            }
            let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
                continue;
            };
            let uid = item.pointer("/metadata/uid").and_then(Value::as_str);
            self.disown_dependents_for_owner(namespace, kind, name, uid)
                .await;
            if self.strip_and_delete(namespace, kind, name, item).await {
                count += 1;
            }
        }
        count
    }

    fn remove_owner_reference_if_present(
        obj: &mut Value,
        owner_kind: &str,
        owner_name: &str,
        owner_uid: Option<&str>,
    ) -> bool {
        let (removed, is_empty) = {
            let Some(owners) = obj
                .pointer_mut("/metadata/ownerReferences")
                .and_then(Value::as_array_mut)
            else {
                return false;
            };

            let initial_len = owners.len();
            owners.retain(|o| {
                let matches = o.get("kind").and_then(Value::as_str) == Some(owner_kind)
                    && (o.get("name").and_then(Value::as_str) == Some(owner_name)
                        || (owner_uid.is_some()
                            && o.get("uid").and_then(Value::as_str) == owner_uid));
                !matches
            });
            (owners.len() != initial_len, owners.is_empty())
        };

        if is_empty && let Some(meta) = obj.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.remove("ownerReferences");
        }

        removed
    }

    async fn disown_dependents_for_owner(
        &self,
        namespace: &str,
        owner_kind: &str,
        owner_name: &str,
        owner_uid: Option<&str>,
    ) {
        if let Ok(list) = self.client.list_pods(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            for mut pod in items.clone() {
                let Some(pname) = pod
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .map(String::from)
                else {
                    continue;
                };
                if Self::remove_owner_reference_if_present(
                    &mut pod, owner_kind, owner_name, owner_uid,
                ) {
                    let _ = self.client.update_pod(namespace, &pname, pod).await;
                }
            }
        }

        if let Ok(list) = self.client.list_replicasets(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            for mut rs in items.clone() {
                let Some(rname) = rs
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .map(String::from)
                else {
                    continue;
                };
                if Self::remove_owner_reference_if_present(
                    &mut rs, owner_kind, owner_name, owner_uid,
                ) {
                    let _ = self.client.update_replicaset(namespace, &rname, rs).await;
                }
            }
        }

        if let Ok(list) = self.client.list_jobs(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            for mut job in items.clone() {
                let Some(jname) = job
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .map(String::from)
                else {
                    continue;
                };
                if Self::remove_owner_reference_if_present(
                    &mut job, owner_kind, owner_name, owner_uid,
                ) {
                    let _ = self.client.update_job(namespace, &jname, job).await;
                }
            }
        }
    }

    pub async fn reconcile_namespace_termination(
        &self,
        namespace: &str,
    ) -> Result<usize, ControllerError> {
        let Ok(ns_doc) = self.client.get_namespace(namespace).await else {
            return Ok(0);
        };

        let is_terminating = ns_doc.pointer("/metadata/deletionTimestamp").is_some()
            || ns_doc.pointer("/status/phase").and_then(Value::as_str) == Some("Terminating");

        if !is_terminating {
            return Ok(0);
        }

        let mut deleted = self.cleanup_terminating_workloads(namespace).await;
        let has_pods = self
            .client
            .list_pods(namespace)
            .await
            .ok()
            .and_then(|l| {
                l.get("items")
                    .and_then(Value::as_array)
                    .map(|a| !a.is_empty())
            })
            .unwrap_or(false);
        if !has_pods {
            deleted += self.cleanup_terminating_storage_and_crds(namespace).await;
        }
        Ok(deleted)
    }

    async fn cleanup_terminating_workloads(&self, namespace: &str) -> usize {
        let mut count = 0;
        if let Ok(list) = self.client.list_pods(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            for item in items {
                let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
                    continue;
                };
                if self.client.delete_pod(namespace, name).await.is_ok() {
                    count += 1;
                }
            }
        }
        if let Ok(list) = self.client.list_replicasets(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            for item in items {
                let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
                    continue;
                };
                if self.client.delete_replicaset(namespace, name).await.is_ok() {
                    count += 1;
                }
            }
        }
        if let Ok(list) = self.client.list_deployments(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            for item in items {
                let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
                    continue;
                };
                if self.client.delete_deployment(namespace, name).await.is_ok() {
                    count += 1;
                }
            }
        }
        if let Ok(list) = self.client.list_jobs(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            for item in items {
                let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
                    continue;
                };
                if self.client.delete_job(namespace, name).await.is_ok() {
                    count += 1;
                }
            }
        }
        count
    }

    async fn cleanup_terminating_crd_instances(&self, namespace: &str, crd: &Value) -> usize {
        let Some(group) = crd.pointer("/spec/group").and_then(Value::as_str) else {
            return 0;
        };
        let Some(plural) = crd.pointer("/spec/names/plural").and_then(Value::as_str) else {
            return 0;
        };
        let Ok(list) = self
            .client
            .list_custom_resources(group, plural, namespace)
            .await
        else {
            return 0;
        };
        let Some(items) = list.get("items").and_then(Value::as_array) else {
            return 0;
        };

        let mut count = 0;
        for item in items {
            let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
                continue;
            };
            if self
                .client
                .delete_custom_resource(group, plural, namespace, name)
                .await
                .is_ok()
            {
                count += 1;
            }
        }
        count
    }

    async fn cleanup_terminating_storage_and_crds(&self, namespace: &str) -> usize {
        let mut count = 0;
        if let Ok(list) = self.client.list_configmaps(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            for item in items {
                let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
                    continue;
                };
                if self
                    .client
                    .delete_configmap(namespace, name, None)
                    .await
                    .is_ok()
                {
                    count += 1;
                }
            }
        }
        if let Ok(list) = self.client.list_secrets(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            for item in items {
                let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
                    continue;
                };
                if self
                    .client
                    .delete_secret(namespace, name, None)
                    .await
                    .is_ok()
                {
                    count += 1;
                }
            }
        }
        if let Ok(crd_list) = self.client.list_crds().await
            && let Some(crds) = crd_list.get("items").and_then(Value::as_array)
        {
            for crd in crds {
                count += self.cleanup_terminating_crd_instances(namespace, crd).await;
            }
        }
        count
    }

    pub async fn finalize_terminating_namespace(
        &self,
        namespace: &str,
    ) -> Result<bool, ControllerError> {
        let Ok(ns_doc) = self.client.get_namespace(namespace).await else {
            return Ok(false);
        };

        let is_terminating = ns_doc.pointer("/metadata/deletionTimestamp").is_some()
            || ns_doc.pointer("/status/phase").and_then(Value::as_str) == Some("Terminating");

        if !is_terminating {
            return Ok(false);
        }

        let has_pods = self
            .client
            .list_pods(namespace)
            .await
            .ok()
            .and_then(|l| {
                l.get("items")
                    .and_then(Value::as_array)
                    .map(|a| !a.is_empty())
            })
            .unwrap_or(false);
        let has_rs = self
            .client
            .list_replicasets(namespace)
            .await
            .ok()
            .and_then(|l| {
                l.get("items")
                    .and_then(Value::as_array)
                    .map(|a| !a.is_empty())
            })
            .unwrap_or(false);

        if !has_pods && !has_rs {
            let _ = self.client.delete_namespace(namespace).await;
            return Ok(true);
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn foreground_deletion_detection() {
        let clean = json!({
            "metadata": { "name": "test" }
        });
        assert!(!has_foreground_deletion(&clean));

        let del_only = json!({
            "metadata": {
                "name": "test",
                "deletionTimestamp": "2026-10-15T00:00:00Z"
            }
        });
        assert!(!has_foreground_deletion(&del_only));

        let finalizer_only = json!({
            "metadata": {
                "name": "test",
                "finalizers": ["foregroundDeletion"]
            }
        });
        assert!(!has_foreground_deletion(&finalizer_only));

        let foreground = json!({
            "metadata": {
                "name": "test",
                "deletionTimestamp": "2026-10-15T00:00:00Z",
                "finalizers": ["foregroundDeletion"]
            }
        });
        assert!(has_foreground_deletion(&foreground));
    }

    #[test]
    fn uid_matching() {
        let item = json!({
            "metadata": { "name": "test", "uid": "abc-123" }
        });
        assert!(matches_uid(&item, None));
        assert!(matches_uid(&item, Some("")));
        assert!(matches_uid(&item, Some("abc-123")));
        assert!(!matches_uid(&item, Some("xyz-789")));
    }

    #[test]
    fn orphan_deletion_detection() {
        let clean = json!({ "metadata": { "name": "test" } });
        assert!(!has_orphan_deletion(&clean));

        let finalizer_only = json!({
            "metadata": {
                "name": "test",
                "finalizers": ["orphan"]
            }
        });
        assert!(!has_orphan_deletion(&finalizer_only));

        let del_with_orphan = json!({
            "metadata": {
                "name": "test",
                "deletionTimestamp": "2026-10-15T00:00:00Z",
                "finalizers": ["orphan"]
            }
        });
        assert!(has_orphan_deletion(&del_with_orphan));

        let del_with_k8s_orphan = json!({
            "metadata": {
                "name": "test",
                "deletionTimestamp": "2026-10-15T00:00:00Z",
                "finalizers": ["kubernetes.io/orphan"]
            }
        });
        assert!(has_orphan_deletion(&del_with_k8s_orphan));
    }

    #[test]
    fn blocks_owner_deletion_evaluation() {
        let explicit_true = json!({ "blockOwnerDeletion": true });
        assert!(blocks_owner_deletion(&explicit_true));

        let explicit_false = json!({ "blockOwnerDeletion": false, "controller": true });
        assert!(!blocks_owner_deletion(&explicit_false));

        let controller_fallback = json!({ "controller": true });
        assert!(blocks_owner_deletion(&controller_fallback));

        let neither = json!({ "name": "owner" });
        assert!(!blocks_owner_deletion(&neither));
    }

    use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
    use diorama_datastore::{DatastoreConfig, DatastoreEngine};
    use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
    use tempfile::TempDir;

    fn setup_test_client(dir: &TempDir) -> Arc<KubernetesApiClient> {
        let node_ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let pki_dir = dir.path().join("pki");
        std::fs::create_dir_all(&pki_dir).unwrap();
        let datastore_dir = dir.path().join("datastore");

        let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "test-node".to_string(), node_ip);
        let pki = ClusterPki::new(pki_config);
        pki.reconcile().expect("PKI reconcile");

        let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir)).unwrap();
        let storage = KubernetesStorage::new(engine.client(), "/registry");

        let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
        let apiserver_service = ApiserverService::new(apiserver_config, storage);

        Arc::new(apiserver_service.controller_manager_client())
    }

    #[tokio::test]
    async fn foreground_cascading_with_block_owner_deletion() {
        let temp = TempDir::new().unwrap();
        let client = setup_test_client(&temp);
        let gc = GarbageCollector::new(client.clone());
        let ns = "fg-cascade-ns";
        client.create_namespace(ns).await.unwrap();

        let dep = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "fg-parent", "namespace": ns },
            "spec": {
                "replicas": 1,
                "selector": { "matchLabels": { "app": "fg" } },
                "template": { "metadata": { "labels": { "app": "fg" } }, "spec": { "containers": [{ "name": "app", "image": "nginx" }] } }
            }
        });
        let created_dep = client.create_deployment(ns, dep).await.unwrap();
        let dep_uid = created_dep
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        let pod_blocking = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "pod-blocking",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": "fg-parent",
                    "uid": dep_uid,
                    "controller": true,
                    "blockOwnerDeletion": true
                }]
            },
            "spec": { "containers": [{ "name": "app", "image": "nginx" }] }
        });
        client.create_pod(ns, pod_blocking).await.unwrap();

        let mut dep_fg = created_dep;
        dep_fg["metadata"]["deletionTimestamp"] = json!("2026-10-15T00:00:00Z");
        dep_fg["metadata"]["finalizers"] = json!(["foregroundDeletion"]);
        client
            .update_deployment(ns, "fg-parent", dep_fg)
            .await
            .unwrap();

        let collected = gc.reconcile(ns).await.unwrap();
        assert!(collected >= 2);
        assert!(client.get_deployment(ns, "fg-parent").await.is_err());
        assert!(client.get_pod(ns, "pod-blocking").await.is_err());
    }

    #[tokio::test]
    async fn multi_owner_references_resolution() {
        let temp = TempDir::new().unwrap();
        let client = setup_test_client(&temp);
        let gc = GarbageCollector::new(client.clone());
        let ns = "multi-owner-ns";
        client.create_namespace(ns).await.unwrap();

        let dep_a = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "dep-a", "namespace": ns },
            "spec": {
                "replicas": 1,
                "selector": { "matchLabels": { "app": "a" } },
                "template": { "metadata": { "labels": { "app": "a" } }, "spec": { "containers": [{ "name": "app", "image": "nginx" }] } }
            }
        });
        let dep_b = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "dep-b", "namespace": ns },
            "spec": {
                "replicas": 1,
                "selector": { "matchLabels": { "app": "b" } },
                "template": { "metadata": { "labels": { "app": "b" } }, "spec": { "containers": [{ "name": "app", "image": "nginx" }] } }
            }
        });

        let created_a = client.create_deployment(ns, dep_a).await.unwrap();
        let created_b = client.create_deployment(ns, dep_b).await.unwrap();
        let uid_a = created_a
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let uid_b = created_b
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        let child_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "multi-owned-pod",
                "namespace": ns,
                "ownerReferences": [
                    { "apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-a", "uid": uid_a },
                    { "apiVersion": "apps/v1", "kind": "Deployment", "name": "dep-b", "uid": uid_b }
                ]
            },
            "spec": { "containers": [{ "name": "app", "image": "nginx" }] }
        });
        client.create_pod(ns, child_pod).await.unwrap();

        // 1. Delete parent A only: child pod must survive because parent B is alive
        client.delete_deployment(ns, "dep-a").await.unwrap();
        let _ = gc.reconcile(ns).await.unwrap();
        assert!(client.get_pod(ns, "multi-owned-pod").await.is_ok());

        // 2. Delete parent B: child pod must now be collected
        client.delete_deployment(ns, "dep-b").await.unwrap();
        let collected = gc.reconcile(ns).await.unwrap();
        assert!(collected >= 1);
        assert!(client.get_pod(ns, "multi-owned-pod").await.is_err());
    }

    #[tokio::test]
    async fn orphan_propagation_policy_disowns_dependents() {
        let temp = TempDir::new().unwrap();
        let client = setup_test_client(&temp);
        let gc = GarbageCollector::new(client.clone());
        let ns = "orphan-test-ns";
        client.create_namespace(ns).await.unwrap();

        let dep = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "orphan-parent", "namespace": ns },
            "spec": {
                "replicas": 1,
                "selector": { "matchLabels": { "app": "orphan" } },
                "template": { "metadata": { "labels": { "app": "orphan" } }, "spec": { "containers": [{ "name": "app", "image": "nginx" }] } }
            }
        });
        let created_dep = client.create_deployment(ns, dep).await.unwrap();
        let dep_uid = created_dep
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        let child_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "orphan-child-pod",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": "orphan-parent",
                    "uid": dep_uid
                }]
            },
            "spec": { "containers": [{ "name": "app", "image": "nginx" }] }
        });
        client.create_pod(ns, child_pod).await.unwrap();

        // Mark orphan-parent for deletion with orphan finalizer
        let mut dep_orphan = created_dep;
        dep_orphan["metadata"]["deletionTimestamp"] = json!("2026-10-15T00:00:00Z");
        dep_orphan["metadata"]["finalizers"] = json!(["orphan"]);
        client
            .update_deployment(ns, "orphan-parent", dep_orphan)
            .await
            .unwrap();

        let _ = gc.reconcile(ns).await.unwrap();

        // Parent must be finalized and deleted
        assert!(client.get_deployment(ns, "orphan-parent").await.is_err());

        // Child pod must survive, and its ownerReferences must be cleared
        let surviving_pod = client.get_pod(ns, "orphan-child-pod").await.unwrap();
        assert!(surviving_pod.pointer("/metadata/ownerReferences").is_none());
    }

    async fn setup_widget_crd(client: &KubernetesApiClient) {
        let crd = json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.com" },
            "spec": {
                "group": "example.com",
                "names": {
                    "kind": "Widget",
                    "plural": "widgets",
                    "singular": "widget"
                },
                "scope": "Namespaced",
                "versions": [{
                    "name": "v1",
                    "served": true,
                    "storage": true,
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "x-kubernetes-preserve-unknown-fields": true
                        }
                    }
                }]
            }
        });
        client.create_crd(crd).await.unwrap();
    }

    #[tokio::test]
    async fn custom_resource_as_owner_resolution() {
        let temp = TempDir::new().unwrap();
        let client = setup_test_client(&temp);
        let gc = GarbageCollector::new(client.clone());
        let ns = "crd-owner-ns";
        client.create_namespace(ns).await.unwrap();
        setup_widget_crd(&client).await;

        let widget = json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "parent-widget", "namespace": ns, "uid": "cr-widget-uid-01" },
            "spec": { "state": "active" }
        });
        let created_widget = client
            .create_custom_resource("example.com", "widgets", ns, "parent-widget", widget)
            .await
            .unwrap();
        let widget_uid = created_widget
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        let child_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "cr-child-pod",
                "namespace": ns,
                "ownerReferences": [{
                    "apiVersion": "example.com/v1",
                    "kind": "Widget",
                    "name": "parent-widget",
                    "uid": widget_uid
                }]
            },
            "spec": { "containers": [{ "name": "app", "image": "nginx" }] }
        });
        client.create_pod(ns, child_pod).await.unwrap();

        let _ = gc.reconcile(ns).await.unwrap();
        assert!(client.get_pod(ns, "cr-child-pod").await.is_ok());

        client
            .delete_custom_resource("example.com", "widgets", ns, "parent-widget")
            .await
            .unwrap();
        let collected = gc.reconcile(ns).await.unwrap();
        assert!(collected >= 1);
        assert!(client.get_pod(ns, "cr-child-pod").await.is_err());
    }

    #[tokio::test]
    async fn custom_resource_as_dependent_resolution() {
        let temp = TempDir::new().unwrap();
        let client = setup_test_client(&temp);
        let gc = GarbageCollector::new(client.clone());
        let ns = "crd-dep-ns";
        client.create_namespace(ns).await.unwrap();
        setup_widget_crd(&client).await;

        let dep = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "cr-parent-deploy", "namespace": ns },
            "spec": {
                "replicas": 1,
                "selector": { "matchLabels": { "app": "cr-test" } },
                "template": { "metadata": { "labels": { "app": "cr-test" } }, "spec": { "containers": [{ "name": "app", "image": "nginx" }] } }
            }
        });
        let created_dep = client.create_deployment(ns, dep).await.unwrap();
        let dep_uid = created_dep
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        let dependent_widget = json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": {
                "name": "child-widget",
                "namespace": ns,
                "uid": "cr-widget-uid-02",
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": "cr-parent-deploy",
                    "uid": dep_uid
                }]
            },
            "spec": { "state": "child" }
        });
        client
            .create_custom_resource(
                "example.com",
                "widgets",
                ns,
                "child-widget",
                dependent_widget,
            )
            .await
            .unwrap();

        client
            .delete_deployment(ns, "cr-parent-deploy")
            .await
            .unwrap();
        let cr_collected = gc.reconcile(ns).await.unwrap();
        assert!(cr_collected >= 1);
        assert!(
            client
                .get_custom_resource("example.com", "widgets", ns, "child-widget")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn namespace_termination_finalizer_cleanup() {
        let temp = TempDir::new().unwrap();
        let client = setup_test_client(&temp);
        let gc = GarbageCollector::new(client.clone());
        let ns = "terminating-test-ns";

        // Create namespace marked as Terminating
        let ns_obj = json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": ns,
                "deletionTimestamp": "2026-10-15T00:00:00Z",
                "finalizers": ["kubernetes"]
            },
            "status": {
                "phase": "Terminating"
            }
        });
        client.create_namespace_object(ns_obj).await.unwrap();

        // Create a pod and configmap inside terminating-test-ns
        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "doomed-ns-pod", "namespace": ns },
            "spec": { "containers": [{ "name": "app", "image": "nginx" }] }
        });
        client.create_pod(ns, pod).await.unwrap();

        let cm = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "doomed-ns-cm", "namespace": ns },
            "data": { "key": "val" }
        });
        client.create_configmap_object(ns, cm).await.unwrap();

        // Reconcile garbage collector
        let collected = gc.reconcile(ns).await.unwrap();
        assert!(collected >= 2);

        // Namespace must be cleaned up and finalized
        assert!(client.get_namespace(ns).await.is_err());
    }
}
