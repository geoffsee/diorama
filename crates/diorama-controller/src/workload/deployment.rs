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

        self.ensure_owned_rs_pod_template_hashes(namespace, &mut owned)
            .await;

        Ok(owned)
    }

    async fn ensure_owned_rs_pod_template_hashes(&self, namespace: &str, owned: &mut [Value]) {
        for rs in owned.iter_mut() {
            let rs_name = rs
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let rs_uid = rs
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let has_hash = rs
                .pointer("/metadata/labels/pod-template-hash")
                .and_then(Value::as_str)
                .is_some_and(|h| !h.is_empty());
            if has_hash {
                continue;
            }
            let rs_template = rs
                .pointer("/spec/template")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let hash = compute_pod_template_hash(&rs_template);

            apply_hash_to_replicaset(rs, &hash);
            if let Ok(updated) = self
                .client
                .update_replicaset(namespace, &rs_name, rs.clone())
                .await
            {
                *rs = updated;
            }
            stamp_matching_pods_hash(&self.client, namespace, &rs_name, &rs_uid, &hash).await;
        }
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

    /// Reconciles a single `Deployment` object by ensuring its child `ReplicaSet`s exist and match spec.
    pub async fn reconcile_deployment(
        &self,
        namespace: &str,
        deployment: &Value,
    ) -> Result<Value, ControllerError> {
        let cfg = parse_deployment_config(deployment)?;

        let owned_rs = self
            .adopt_and_release_replicasets(
                namespace,
                cfg.name,
                cfg.uid,
                cfg.deleting,
                &cfg.selector,
            )
            .await?;

        let current_hash = compute_pod_template_hash(&cfg.template);
        let prep =
            prepare_replicaset_template_and_selector(&cfg.template, &cfg.selector, &current_hash);

        let (mut new_rs, mut old_rs) =
            find_new_and_old_rs(owned_rs, &current_hash, &prep.template, &cfg.template);
        let new_rev = resolve_revision(new_rs.as_ref(), &old_rs);

        if !cfg.deleting && !cfg.paused {
            let ctx = RolloutContext {
                namespace,
                name: cfg.name,
                uid: cfg.uid,
                desired_replicas: cfg.desired_replicas,
                deployment,
                prep: &prep,
                current_hash: &current_hash,
                new_rev: &new_rev,
            };
            if cfg.strategy_type == "Recreate" {
                self.reconcile_recreate_rollout(&ctx, &mut new_rs, &mut old_rs)
                    .await?;
            } else {
                self.reconcile_rolling_update_rollout(&ctx, &mut new_rs, &mut old_rs)
                    .await?;
            }
        }

        let active_rs_name = resolve_active_rs_name(new_rs.as_ref(), &old_rs, cfg.name);

        let (total_replicas, updated_replicas, ready_replicas, available_replicas) = self
            .compute_deployment_status_counts(namespace, cfg.name, new_rs.as_ref(), &old_rs)
            .await;

        let all_old_zero = old_rs
            .iter()
            .all(|rs| get_rs_spec_replicas(rs) == 0 && get_rs_replicas(rs) == 0);

        let is_rollout_complete = new_rs.is_some()
            && updated_replicas >= cfg.desired_replicas
            && ready_replicas >= cfg.desired_replicas
            && available_replicas >= cfg.desired_replicas
            && all_old_zero;

        let mut updated_deployment = deployment.clone();
        apply_deployment_status(
            &mut updated_deployment,
            &active_rs_name,
            cfg.desired_replicas,
            total_replicas,
            updated_replicas,
            ready_replicas,
            available_replicas,
            cfg.observed_generation,
            &new_rev,
            is_rollout_complete,
        );

        if updated_deployment.get("status") == deployment.get("status")
            && updated_deployment.pointer("/metadata/annotations")
                == deployment.pointer("/metadata/annotations")
        {
            return Ok(updated_deployment);
        }

        self.client
            .update_deployment(namespace, cfg.name, updated_deployment)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("deployments/{}", cfg.name),
                reason: e.to_string(),
            })
    }

    async fn reconcile_recreate_rollout(
        &self,
        ctx: &RolloutContext<'_>,
        new_rs: &mut Option<Value>,
        old_rs: &mut [Value],
    ) -> Result<(), ControllerError> {
        for old in old_rs.iter_mut() {
            if get_rs_spec_replicas(old) > 0 {
                set_rs_spec_replicas(old, 0);
                let old_name = old
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let _ = self
                    .client
                    .update_replicaset(ctx.namespace, old_name, old.clone())
                    .await;
            }
        }

        let old_rs_names: Vec<&str> = old_rs
            .iter()
            .filter_map(|rs| rs.pointer("/metadata/name").and_then(Value::as_str))
            .collect();
        let old_pods_exist = self
            .count_pods_for_rs_names(ctx.namespace, &old_rs_names)
            .await
            > 0;
        let target_new = if old_pods_exist {
            0
        } else {
            ctx.desired_replicas
        };

        if let Some(rs) = new_rs {
            if get_rs_spec_replicas(rs) != target_new {
                set_rs_spec_replicas(rs, target_new);
                let rs_name = rs
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let updated = self
                    .client
                    .update_replicaset(ctx.namespace, rs_name, rs.clone())
                    .await
                    .map_err(|e| ControllerError::ReconciliationFailed {
                        resource: format!("replicasets/{rs_name}"),
                        reason: e.to_string(),
                    })?;
                *rs = updated;
            }
        } else {
            let created = self
                .create_child_rs(ctx, target_new, old_rs.is_empty())
                .await?;
            *new_rs = Some(created);
        }
        Ok(())
    }

    async fn reconcile_rolling_update_rollout(
        &self,
        ctx: &RolloutContext<'_>,
        new_rs: &mut Option<Value>,
        old_rs: &mut [Value],
    ) -> Result<(), ControllerError> {
        let max_surge = resolve_int_or_percent(
            ctx.deployment
                .pointer("/spec/strategy/rollingUpdate/maxSurge"),
            ctx.desired_replicas,
            true,
        );
        let max_unavailable = resolve_int_or_percent(
            ctx.deployment
                .pointer("/spec/strategy/rollingUpdate/maxUnavailable"),
            ctx.desired_replicas,
            false,
        );
        let max_total_replicas = ctx.desired_replicas + max_surge;

        let total_old_spec: i64 = old_rs.iter().map(get_rs_spec_replicas).sum();
        let new_spec = new_rs.as_ref().map_or(0, get_rs_spec_replicas);
        let mut current_total_spec = new_spec + total_old_spec;

        if !old_rs.is_empty()
            && total_old_spec > 0
            && (current_total_spec > max_total_replicas
                || current_total_spec < ctx.desired_replicas)
            && current_total_spec > 0
        {
            let scaled = self
                .apply_proportional_scale(
                    ctx.namespace,
                    new_rs.as_mut(),
                    old_rs,
                    max_total_replicas,
                )
                .await;
            if scaled {
                return Ok(());
            }
        }

        self.cleanup_unhealthy_old_replicas(ctx, old_rs, &mut current_total_spec)
            .await;

        self.ensure_and_scale_new_rs(ctx, new_rs, old_rs, max_total_replicas)
            .await?;
        self.reconcile_scale_down_old(ctx, new_rs.as_ref(), old_rs, max_unavailable)
            .await;
        Ok(())
    }

    async fn cleanup_unhealthy_old_replicas(
        &self,
        ctx: &RolloutContext<'_>,
        old_rs: &mut [Value],
        current_total_spec: &mut i64,
    ) {
        if *current_total_spec <= ctx.desired_replicas {
            return;
        }

        for old in old_rs.iter_mut() {
            if *current_total_spec <= ctx.desired_replicas {
                break;
            }
            let spec_rep = get_rs_spec_replicas(old);
            let (_, avail) = self
                .get_rs_ready_and_available(ctx.namespace, old, ctx.name)
                .await;
            if spec_rep <= avail {
                continue;
            }
            let unhealthy = spec_rep - avail;
            let cleanup_count = unhealthy.min(*current_total_spec - ctx.desired_replicas);
            if cleanup_count > 0 {
                cleanup_old_replicaset(&self.client, ctx.namespace, old, spec_rep, cleanup_count)
                    .await;
                *current_total_spec -= cleanup_count;
            }
        }
    }

    async fn ensure_and_scale_new_rs(
        &self,
        ctx: &RolloutContext<'_>,
        new_rs: &mut Option<Value>,
        old_rs: &[Value],
        max_total_replicas: i64,
    ) -> Result<(), ControllerError> {
        if new_rs.is_none() {
            let cur_old: i64 = old_rs.iter().map(get_rs_spec_replicas).sum();
            let initial_new = (max_total_replicas - cur_old)
                .max(0)
                .min(ctx.desired_replicas);
            let created = self
                .create_child_rs(ctx, initial_new, old_rs.is_empty())
                .await?;
            *new_rs = Some(created);
        }

        if let Some(rs) = new_rs {
            let cur_old: i64 = old_rs.iter().map(get_rs_spec_replicas).sum();
            let max_allowed = (max_total_replicas - cur_old)
                .max(0)
                .min(ctx.desired_replicas);
            let cur = get_rs_spec_replicas(rs);
            let target_new = max_allowed.max(cur).min(ctx.desired_replicas);
            if cur != target_new {
                set_rs_spec_replicas(rs, target_new);
                let rs_name = rs
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let updated = self
                    .client
                    .update_replicaset(ctx.namespace, rs_name, rs.clone())
                    .await
                    .map_err(|e| ControllerError::ReconciliationFailed {
                        resource: format!("replicasets/{rs_name}"),
                        reason: e.to_string(),
                    })?;
                *rs = updated;
            }
        }
        Ok(())
    }

    async fn reconcile_scale_down_old(
        &self,
        ctx: &RolloutContext<'_>,
        new_rs: Option<&Value>,
        old_rs: &mut [Value],
        max_unavailable: i64,
    ) {
        let (new_ready, new_avail) = if let Some(rs) = new_rs {
            self.get_rs_ready_and_available(ctx.namespace, rs, ctx.name)
                .await
        } else {
            (0, 0)
        };

        let mut old_avail_total = 0;
        for old in old_rs.iter() {
            let (_, avail) = self
                .get_rs_ready_and_available(ctx.namespace, old, ctx.name)
                .await;
            old_avail_total += avail;
        }

        let total_available = new_avail + old_avail_total;
        let min_available = ctx.desired_replicas.saturating_sub(max_unavailable).max(0);
        let max_scaledown = total_available.saturating_sub(min_available).max(0);

        if max_scaledown == 0 {
            return;
        }

        let cur_old: i64 = old_rs.iter().map(get_rs_spec_replicas).sum();
        let target_total_old = if new_ready >= ctx.desired_replicas {
            0
        } else {
            (ctx.desired_replicas - new_ready)
                .saturating_sub(max_unavailable)
                .max(0)
        };

        let desired_scaledown = cur_old.saturating_sub(target_total_old);
        let allowed_scaledown = desired_scaledown.min(max_scaledown);
        let actual_target_total_old = cur_old - allowed_scaledown;

        scale_down_old_replicasets(
            &self.client,
            ctx.namespace,
            old_rs,
            actual_target_total_old,
            cur_old,
        )
        .await;
    }

    async fn apply_proportional_scale(
        &self,
        namespace: &str,
        mut new_rs: Option<&mut Value>,
        old_rs: &mut [Value],
        desired_replicas: i64,
    ) -> bool {
        let changed = scale_proportionally(new_rs.as_deref_mut(), old_rs, desired_replicas);
        if !changed {
            return false;
        }
        if let Some(new) = new_rs {
            let new_name = new
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let _ = self
                .client
                .update_replicaset(namespace, new_name, new.clone())
                .await;
        }
        for old in old_rs.iter_mut() {
            let old_name = old
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let _ = self
                .client
                .update_replicaset(namespace, old_name, old.clone())
                .await;
        }
        true
    }

    async fn create_child_rs(
        &self,
        ctx: &RolloutContext<'_>,
        replicas: i64,
        is_initial: bool,
    ) -> Result<Value, ControllerError> {
        let default_rs_name = format!("{}-rs", ctx.name);
        let rs_name = if is_initial
            && self
                .client
                .get_replicaset(ctx.namespace, &default_rs_name)
                .await
                .is_err()
        {
            default_rs_name
        } else {
            format!("{}-{}", ctx.name, ctx.current_hash)
        };

        if let Ok(existing) = self.client.get_replicaset(ctx.namespace, &rs_name).await {
            return Ok(existing);
        }

        let new_rs = json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": {
                "name": rs_name,
                "namespace": ctx.namespace,
                "labels": ctx.prep.labels,
                "annotations": {
                    "deployment.kubernetes.io/revision": ctx.new_rev
                },
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": ctx.name,
                    "uid": ctx.uid,
                    "controller": true,
                    "blockOwnerDeletion": true
                }]
            },
            "spec": {
                "replicas": replicas,
                "selector": ctx.prep.selector,
                "template": ctx.prep.template
            }
        });

        self.client
            .create_replicaset(ctx.namespace, new_rs)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("replicasets/{rs_name}"),
                reason: e.to_string(),
            })
    }

    async fn count_pods_for_rs_names(&self, namespace: &str, rs_names: &[&str]) -> usize {
        let Ok(pod_list) = self.client.list_pods(namespace).await else {
            return 0;
        };
        let Some(items) = pod_list.get("items").and_then(Value::as_array) else {
            return 0;
        };
        items
            .iter()
            .filter(|p| is_pod_owned_by_rs_names(p, rs_names))
            .count()
    }

    async fn compute_deployment_status_counts(
        &self,
        namespace: &str,
        dep_name: &str,
        new_rs: Option<&Value>,
        old_rs: &[Value],
    ) -> (i64, i64, i64, i64) {
        let mut total_replicas = 0;
        let mut ready_replicas = 0;
        let mut available_replicas = 0;
        let mut updated_replicas = 0;

        let pod_list = self.client.list_pods(namespace).await.ok();
        let items = pod_list
            .as_ref()
            .and_then(|l| l.get("items"))
            .and_then(Value::as_array);

        if let Some(rs) = new_rs {
            let rs_name = rs
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            if let Some(pods) = items {
                let matching: Vec<&Value> = pods
                    .iter()
                    .filter(|p| is_pod_owned_by_workload(p, rs_name, dep_name))
                    .collect();
                let actual = i64::try_from(matching.len()).unwrap_or(0);
                let ready =
                    i64::try_from(matching.iter().filter(|p| super::is_pod_ready(p)).count())
                        .unwrap_or(0);
                total_replicas += actual;
                updated_replicas = actual;
                ready_replicas += ready;
                available_replicas += ready;
            } else {
                let (ready, avail) = self
                    .get_rs_ready_and_available(namespace, rs, dep_name)
                    .await;
                let actual = get_rs_replicas(rs);
                total_replicas += actual;
                updated_replicas = actual;
                ready_replicas += ready;
                available_replicas += avail;
            }
        }

        for old in old_rs {
            let rs_name = old
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            if let Some(pods) = items {
                let matching: Vec<&Value> = pods
                    .iter()
                    .filter(|p| is_pod_owned_by_workload(p, rs_name, dep_name))
                    .collect();
                let actual = i64::try_from(matching.len()).unwrap_or(0);
                let ready =
                    i64::try_from(matching.iter().filter(|p| super::is_pod_ready(p)).count())
                        .unwrap_or(0);
                total_replicas += actual;
                ready_replicas += ready;
                available_replicas += ready;
            } else {
                let (ready, avail) = self
                    .get_rs_ready_and_available(namespace, old, dep_name)
                    .await;
                total_replicas += get_rs_replicas(old);
                ready_replicas += ready;
                available_replicas += avail;
            }
        }

        (
            total_replicas,
            updated_replicas,
            ready_replicas,
            available_replicas,
        )
    }

    async fn get_rs_ready_and_available(
        &self,
        namespace: &str,
        rs: &Value,
        dep_name: &str,
    ) -> (i64, i64) {
        let rs_name = rs
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !rs_name.is_empty()
            && let Ok(pod_list) = self.client.list_pods(namespace).await
            && let Some(items) = pod_list.get("items").and_then(Value::as_array)
        {
            let count = items
                .iter()
                .filter(|p| {
                    is_pod_owned_by_workload(p, rs_name, dep_name) && super::is_pod_ready(p)
                })
                .count();
            let ready = i64::try_from(count).unwrap_or(0);
            return (ready, ready);
        }

        let ready = rs
            .pointer("/status/readyReplicas")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let available = rs
            .pointer("/status/availableReplicas")
            .and_then(Value::as_i64)
            .unwrap_or(ready);
        (ready, available)
    }
}

struct RolloutContext<'a> {
    namespace: &'a str,
    name: &'a str,
    uid: &'a str,
    desired_replicas: i64,
    deployment: &'a Value,
    prep: &'a PreparedReplicaSetSpec,
    current_hash: &'a str,
    new_rev: &'a str,
}

struct DeploymentConfig<'a> {
    name: &'a str,
    uid: &'a str,
    deleting: bool,
    paused: bool,
    desired_replicas: i64,
    selector: Value,
    template: Value,
    observed_generation: i64,
    strategy_type: &'a str,
}

fn parse_deployment_config(dep: &Value) -> Result<DeploymentConfig<'_>, ControllerError> {
    let name = dep
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .ok_or_else(|| ControllerError::InvalidConfiguration {
            field: "metadata.name".to_string(),
            reason: "Deployment missing metadata.name".to_string(),
        })?;
    let uid = dep
        .get("metadata")
        .and_then(|m| m.get("uid"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let deleting = dep
        .pointer("/metadata/deletionTimestamp")
        .and_then(Value::as_str)
        .is_some();
    let paused = dep
        .pointer("/spec/paused")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let desired_replicas = dep
        .get("spec")
        .and_then(|s| s.get("replicas"))
        .and_then(Value::as_i64)
        .unwrap_or(1);
    let selector = dep
        .get("spec")
        .and_then(|s| s.get("selector"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let template = dep
        .get("spec")
        .and_then(|s| s.get("template"))
        .cloned()
        .unwrap_or_else(|| json!({ "spec": { "containers": [] } }));
    let observed_generation = dep
        .pointer("/metadata/generation")
        .and_then(Value::as_i64)
        .unwrap_or(1);
    let strategy_type = dep
        .pointer("/spec/strategy/type")
        .and_then(Value::as_str)
        .unwrap_or("RollingUpdate");

    Ok(DeploymentConfig {
        name,
        uid,
        deleting,
        paused,
        desired_replicas,
        selector,
        template,
        observed_generation,
        strategy_type,
    })
}

fn equal_ignore_hash(rs_tpl: &Value, spec_tpl: &Value) -> bool {
    let mut clean_rs = rs_tpl.clone();
    if let Some(labels) = clean_rs
        .pointer_mut("/metadata/labels")
        .and_then(Value::as_object_mut)
    {
        labels.remove("pod-template-hash");
    }
    let mut clean_spec = spec_tpl.clone();
    if let Some(labels) = clean_spec
        .pointer_mut("/metadata/labels")
        .and_then(Value::as_object_mut)
    {
        labels.remove("pod-template-hash");
    }
    clean_rs == clean_spec
}

fn find_new_and_old_rs(
    owned_rs: Vec<Value>,
    current_hash: &str,
    prep_template: &Value,
    orig_template: &Value,
) -> (Option<Value>, Vec<Value>) {
    let mut new_rs_idx = None;
    for (i, rs) in owned_rs.iter().enumerate() {
        let rs_hash = rs
            .pointer("/metadata/labels/pod-template-hash")
            .and_then(Value::as_str);
        if rs_hash == Some(current_hash) {
            new_rs_idx = Some(i);
            break;
        }
        if let Some(rs_tpl) = rs.pointer("/spec/template")
            && (rs_tpl == prep_template
                || rs_tpl == orig_template
                || equal_ignore_hash(rs_tpl, orig_template))
        {
            new_rs_idx = Some(i);
            break;
        }
    }
    let mut remaining = owned_rs;
    let new_rs = new_rs_idx.map(|i| remaining.remove(i));
    (new_rs, remaining)
}

fn resolve_revision(new_rs: Option<&Value>, old_rs: &[Value]) -> String {
    let max_rev = old_rs
        .iter()
        .chain(new_rs)
        .filter_map(|rs| {
            rs.pointer("/metadata/annotations/deployment.kubernetes.io~1revision")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<u64>().ok())
        })
        .max()
        .unwrap_or(0);

    new_rs
        .and_then(|rs| {
            rs.pointer("/metadata/annotations/deployment.kubernetes.io~1revision")
                .and_then(Value::as_str)
        })
        .map_or_else(|| (max_rev + 1).to_string(), str::to_string)
}

fn resolve_active_rs_name(new_rs: Option<&Value>, old_rs: &[Value], dep_name: &str) -> String {
    new_rs
        .and_then(|rs| rs.pointer("/metadata/name").and_then(Value::as_str))
        .or_else(|| {
            old_rs
                .first()
                .and_then(|rs| rs.pointer("/metadata/name").and_then(Value::as_str))
        })
        .unwrap_or(dep_name)
        .to_string()
}

async fn scale_down_old_replicasets(
    client: &KubernetesApiClient,
    namespace: &str,
    old_rs: &mut [Value],
    target_total_old: i64,
    current_old_spec: i64,
) {
    if current_old_spec <= target_total_old {
        return;
    }
    let mut remaining = current_old_spec - target_total_old;
    for old in old_rs.iter_mut() {
        if remaining == 0 {
            break;
        }
        let cur = get_rs_spec_replicas(old);
        if cur > 0 {
            let reduce = cur.min(remaining);
            remaining -= reduce;
            set_rs_spec_replicas(old, cur - reduce);
            let old_name = old
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let _ = client
                .update_replicaset(namespace, old_name, old.clone())
                .await;
        }
    }
}

async fn cleanup_old_replicaset(
    client: &KubernetesApiClient,
    namespace: &str,
    old: &mut Value,
    spec_rep: i64,
    cleanup_count: i64,
) {
    let target_replicas = spec_rep - cleanup_count;
    set_rs_spec_replicas(old, target_replicas);
    if let Some(old_name) = old.pointer("/metadata/name").and_then(Value::as_str) {
        let _ = client
            .update_replicaset(namespace, old_name, old.clone())
            .await;
    }
}

fn is_pod_owned_by_rs_names(pod: &Value, rs_names: &[&str]) -> bool {
    let Some(owners) = pod
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
    else {
        return false;
    };
    owners.iter().any(|o| {
        o.get("kind").and_then(Value::as_str) == Some("ReplicaSet")
            && o.get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| rs_names.contains(&n))
    })
}

fn scale_proportionally(
    new_rs: Option<&mut Value>,
    old_rs: &mut [Value],
    desired_replicas: i64,
) -> bool {
    let mut all_rs: Vec<&mut Value> = Vec::new();
    if let Some(n) = new_rs {
        all_rs.push(n);
    }
    for o in old_rs.iter_mut() {
        all_rs.push(o);
    }
    let current_total: i64 = all_rs.iter().map(|rs| get_rs_spec_replicas(rs)).sum();
    if current_total == 0 || current_total == desired_replicas {
        return false;
    }
    let mut new_targets = Vec::new();
    for rs in &all_rs {
        let cur = get_rs_spec_replicas(rs);
        #[allow(clippy::cast_precision_loss)]
        let proportion = (cur as f64) / (current_total as f64);
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let target = (desired_replicas as f64 * proportion).round() as i64;
        new_targets.push(target);
    }
    let sum_targets: i64 = new_targets.iter().sum();
    let mut diff = desired_replicas - sum_targets;
    while diff > 0 {
        for target in &mut new_targets {
            if diff == 0 {
                break;
            }
            *target += 1;
            diff -= 1;
        }
    }
    while diff < 0 {
        for target in &mut new_targets {
            if diff == 0 {
                break;
            }
            if *target > 0 {
                *target -= 1;
                diff += 1;
            }
        }
    }
    let mut changed = false;
    for (rs, target) in all_rs.into_iter().zip(new_targets) {
        if get_rs_spec_replicas(rs) != target {
            set_rs_spec_replicas(rs, target);
            changed = true;
        }
    }
    changed
}

fn resolve_int_or_percent(val: Option<&Value>, desired: i64, is_round_up: bool) -> i64 {
    if desired <= 0 {
        return 0;
    }
    match val {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0).max(0),
        Some(Value::String(s)) => {
            if let Some(pct_str) = s.strip_suffix('%') {
                if let Ok(pct) = pct_str.parse::<i64>() {
                    let product = desired * pct;
                    if is_round_up {
                        (product + 99) / 100
                    } else {
                        product / 100
                    }
                } else {
                    default_surge_or_unavail(desired, is_round_up)
                }
            } else if let Ok(num) = s.parse::<i64>() {
                num.max(0)
            } else {
                default_surge_or_unavail(desired, is_round_up)
            }
        },
        _ => default_surge_or_unavail(desired, is_round_up),
    }
}

fn default_surge_or_unavail(desired: i64, is_round_up: bool) -> i64 {
    if desired <= 0 {
        return 0;
    }
    let product = desired * 25;
    if is_round_up {
        (product + 99) / 100
    } else {
        product / 100
    }
}

fn get_rs_spec_replicas(rs: &Value) -> i64 {
    rs.pointer("/spec/replicas")
        .and_then(Value::as_i64)
        .unwrap_or(1)
}

fn set_rs_spec_replicas(rs: &mut Value, replicas: i64) {
    if let Some(spec) = rs.get_mut("spec").and_then(Value::as_object_mut) {
        spec.insert("replicas".to_string(), json!(replicas));
    }
}

fn get_rs_replicas(rs: &Value) -> i64 {
    rs.pointer("/status/replicas")
        .and_then(Value::as_i64)
        .or_else(|| rs.pointer("/spec/replicas").and_then(Value::as_i64))
        .unwrap_or(0)
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

pub(crate) fn compute_pod_template_hash(template: &Value) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut clean_template = template.clone();
    if let Some(labels) = clean_template
        .pointer_mut("/metadata/labels")
        .and_then(Value::as_object_mut)
    {
        labels.remove("pod-template-hash");
    }
    clean_template.to_string().hash(&mut hasher);
    format!("{:x}", hasher.finish() & 0xffff_ffff)
}

fn prepare_replicaset_template_and_selector(
    template: &Value,
    selector: &Value,
    pod_template_hash: &str,
) -> PreparedReplicaSetSpec {
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
            lbls.insert("pod-template-hash".to_string(), json!(pod_template_hash));
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
    if let Some(lbls) = rs_labels.as_object_mut() {
        lbls.insert("pod-template-hash".to_string(), json!(pod_template_hash));
    }

    PreparedReplicaSetSpec {
        template: rs_template,
        selector: rs_selector,
        labels: rs_labels,
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_deployment_status(
    deployment: &mut Value,
    child_rs_name: &str,
    desired_replicas: i64,
    total_replicas: i64,
    updated_replicas: i64,
    ready_replicas: i64,
    available_replicas: i64,
    observed_generation: i64,
    revision: &str,
    is_rollout_complete: bool,
) {
    let unavailable_replicas = (desired_replicas - available_replicas).max(0);

    let (avail_status, avail_reason, avail_msg) = if available_replicas >= desired_replicas {
        (
            "True",
            "MinimumReplicasAvailable",
            "Deployment has minimum availability.",
        )
    } else {
        (
            "False",
            "MinimumReplicasUnavailable",
            "Deployment does not have minimum availability.",
        )
    };

    let (prog_reason, prog_msg) = if is_rollout_complete {
        (
            "NewReplicaSetAvailable",
            format!("ReplicaSet \"{child_rs_name}\" has successfully progressed."),
        )
    } else {
        (
            "ReplicaSetUpdated",
            format!("ReplicaSet \"{child_rs_name}\" is progressing."),
        )
    };

    let conditions = json!([
        {
            "type": "Available",
            "status": avail_status,
            "reason": avail_reason,
            "message": avail_msg
        },
        {
            "type": "Progressing",
            "status": "True",
            "reason": prog_reason,
            "message": prog_msg
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
            ann_obj.insert(
                "deployment.kubernetes.io/revision".to_string(),
                json!(revision),
            );
        }
    }
    if let Some(status) = deployment.get_mut("status").and_then(Value::as_object_mut) {
        status.insert("replicas".to_string(), json!(total_replicas));
        status.insert("readyReplicas".to_string(), json!(ready_replicas));
        status.insert("availableReplicas".to_string(), json!(available_replicas));
        status.insert(
            "unavailableReplicas".to_string(),
            json!(unavailable_replicas),
        );
        status.insert("updatedReplicas".to_string(), json!(updated_replicas));
        status.insert("observedGeneration".to_string(), json!(observed_generation));
        status.insert("conditions".to_string(), conditions);
    } else if let Some(dep_obj) = deployment.as_object_mut() {
        dep_obj.insert(
            "status".to_string(),
            json!({
                "replicas": total_replicas,
                "readyReplicas": ready_replicas,
                "availableReplicas": available_replicas,
                "unavailableReplicas": unavailable_replicas,
                "updatedReplicas": updated_replicas,
                "observedGeneration": observed_generation,
                "conditions": conditions
            }),
        );
    }
}

fn apply_hash_to_replicaset(rs: &mut Value, hash: &str) {
    if let Some(meta) = rs.get_mut("metadata").and_then(Value::as_object_mut) {
        let labels = meta
            .entry("labels".to_string())
            .or_insert_with(|| json!({}));
        if let Some(l) = labels.as_object_mut() {
            l.insert("pod-template-hash".to_string(), json!(hash));
        }
    }
    if let Some(spec) = rs.get_mut("spec").and_then(Value::as_object_mut) {
        let selector = spec
            .entry("selector".to_string())
            .or_insert_with(|| json!({}));
        if let Some(sel_obj) = selector.as_object_mut() {
            let match_labels = sel_obj
                .entry("matchLabels".to_string())
                .or_insert_with(|| json!({}));
            if let Some(ml) = match_labels.as_object_mut() {
                ml.insert("pod-template-hash".to_string(), json!(hash));
            }
        }
        let tpl = spec
            .entry("template".to_string())
            .or_insert_with(|| json!({}));
        if let Some(tpl_obj) = tpl.as_object_mut() {
            let tpl_meta = tpl_obj
                .entry("metadata".to_string())
                .or_insert_with(|| json!({}));
            if let Some(meta_obj) = tpl_meta.as_object_mut() {
                let labels = meta_obj
                    .entry("labels".to_string())
                    .or_insert_with(|| json!({}));
                if let Some(l) = labels.as_object_mut() {
                    l.insert("pod-template-hash".to_string(), json!(hash));
                }
            }
        }
    }
}

async fn stamp_matching_pods_hash(
    client: &KubernetesApiClient,
    namespace: &str,
    rs_name: &str,
    rs_uid: &str,
    hash: &str,
) {
    let Ok(pod_list) = client.list_pods(namespace).await else {
        return;
    };
    let pods = pod_list
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for mut pod in pods {
        let is_owned = super::is_pod_owned_by(&pod, "ReplicaSet", rs_name, rs_uid);
        let matches_name = pod
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .is_some_and(|n| n.starts_with(rs_name));
        if !is_owned && !matches_name {
            continue;
        }
        let cur_hash = pod
            .pointer("/metadata/labels/pod-template-hash")
            .and_then(Value::as_str);
        if cur_hash == Some(hash) {
            continue;
        }
        if let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut) {
            let labels = meta
                .entry("labels".to_string())
                .or_insert_with(|| json!({}));
            if let Some(l) = labels.as_object_mut() {
                l.insert("pod-template-hash".to_string(), json!(hash));
            }
        }
        if let Some(pname) = pod
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .map(str::to_string)
        {
            let _ = client.update_pod(namespace, &pname, pod).await;
        }
    }
}
