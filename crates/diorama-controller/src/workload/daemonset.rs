use std::collections::BTreeSet;
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

    /// Reconciles a single `DaemonSet` by ensuring a pod exists on each matching schedulable node.
    pub async fn reconcile_daemonset(
        &self,
        namespace: &str,
        ds: &Value,
    ) -> Result<Value, ControllerError> {
        let p = parse_daemonset_params(ds)?;

        let owned_revs = self
            .adopt_and_release_controller_revisions(
                namespace,
                p.name,
                p.uid,
                p.deleting,
                &p.selector_val,
            )
            .await?;

        let rev_hash = if p.deleting {
            String::new()
        } else {
            self.ensure_daemonset_revision(namespace, &p, &owned_revs)
                .await?
        };

        let owned_pods = super::adopt_and_release_pods(
            &self.client,
            namespace,
            "apps/v1",
            "DaemonSet",
            p.name,
            p.uid,
            p.deleting,
            Some(&p.selector_val),
        )
        .await?;

        let node_list = self.client.list_nodes().await.ok();
        let raw_nodes = node_list
            .as_ref()
            .and_then(|n| n.get("items").and_then(Value::as_array))
            .cloned()
            .unwrap_or_default();

        let schedulable_nodes = filter_schedulable_nodes(&raw_nodes);
        let matching_node_names = find_matching_node_names(&schedulable_nodes, &p.template_spec);

        let max_unavailable = parse_max_unavailable(ds, matching_node_names.len());
        let cfg = DaemonSetConfig {
            name: p.name,
            uid: p.uid,
            generation: p.generation,
            rev_hash: &rev_hash,
            update_strategy: &p.update_strategy,
            max_unavailable,
        };

        if !p.deleting {
            self.sync_daemonset_pods(
                namespace,
                &cfg,
                &p.template_spec,
                &p.template_labels,
                &matching_node_names,
                &owned_pods,
            )
            .await?;
        }

        let updated_pods = super::adopt_and_release_pods(
            &self.client,
            namespace,
            "apps/v1",
            "DaemonSet",
            p.name,
            p.uid,
            p.deleting,
            Some(&p.selector_val),
        )
        .await?;

        let status_val = compute_daemonset_status(
            ds,
            p.deleting,
            &matching_node_names,
            &updated_pods,
            p.name,
            &rev_hash,
        );

        let mut updated_ds = ds.clone();
        if let Some(ds_obj) = updated_ds.as_object_mut() {
            ds_obj.insert("status".to_string(), status_val);
        }

        if updated_ds.get("status") == ds.get("status") {
            return Ok(updated_ds);
        }

        self.client
            .update_daemonset(namespace, p.name, updated_ds)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("daemonsets/{}", p.name),
                reason: e.to_string(),
            })
    }

    async fn adopt_and_release_controller_revisions(
        &self,
        namespace: &str,
        ds_name: &str,
        ds_uid: &str,
        ds_deleting: bool,
        selector: &Value,
    ) -> Result<Vec<Value>, ControllerError> {
        let rev_list = self
            .client
            .list_namespaced_objects(
                "apps",
                "ControllerRevisionList",
                "controllerrevisions",
                namespace,
            )
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: "controllerrevisions".to_string(),
                reason: e.to_string(),
            })?;

        let all_revs = rev_list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut owned = Vec::new();
        for mut rev in all_revs {
            let not_terminating = rev.pointer("/metadata/deletionTimestamp").is_none();
            if !not_terminating {
                continue;
            }
            let Some(rev_name) = rev
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                continue;
            };

            let rev_labels = rev.pointer("/metadata/labels");
            let label_matches = super::matches_label_selector(selector, rev_labels);
            let owners = rev
                .pointer("/metadata/ownerReferences")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            let is_owned_by_us = owners.iter().any(|o| {
                let matches_kind = o.get("kind").and_then(Value::as_str) == Some("DaemonSet");
                let matches_uid =
                    !ds_uid.is_empty() && o.get("uid").and_then(Value::as_str) == Some(ds_uid);
                let matches_name = o.get("name").and_then(Value::as_str) == Some(ds_name);
                matches_kind && (matches_uid || matches_name)
            });

            let has_any_controller = owners
                .iter()
                .any(|o| o.get("controller").and_then(Value::as_bool) == Some(true));

            if is_owned_by_us {
                if label_matches {
                    owned.push(rev);
                } else {
                    strip_daemonset_owner_ref(&mut rev, ds_name, ds_uid);
                    let _ = self
                        .client
                        .replace_namespaced_object(
                            "apps",
                            "ControllerRevision",
                            "controllerrevisions",
                            namespace,
                            &rev_name,
                            rev,
                        )
                        .await;
                }
            } else if !ds_deleting && !has_any_controller && label_matches {
                add_daemonset_owner_ref(&mut rev, ds_name, ds_uid);
                if let Ok(updated) = self
                    .client
                    .replace_namespaced_object(
                        "apps",
                        "ControllerRevision",
                        "controllerrevisions",
                        namespace,
                        &rev_name,
                        rev.clone(),
                    )
                    .await
                {
                    owned.push(updated);
                } else {
                    owned.push(rev);
                }
            }
        }

        Ok(owned)
    }

    async fn ensure_daemonset_revision(
        &self,
        namespace: &str,
        p: &DaemonSetParams<'_>,
        owned_revs: &[Value],
    ) -> Result<String, ControllerError> {
        let max_rev = owned_revs
            .iter()
            .filter_map(|r| r.get("revision").and_then(Value::as_i64))
            .max()
            .unwrap_or(0);

        if let Some(matching) = owned_revs
            .iter()
            .find(|r| cr_matches_template(r, &p.template))
        {
            let rev_hash = extract_cr_hash(matching, p.name);
            let rev_num = matching
                .get("revision")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if rev_num < max_rev {
                let mut updated = matching.clone();
                if let Some(obj) = updated.as_object_mut() {
                    obj.insert("revision".to_string(), json!(max_rev + 1));
                }
                if let Some(name) = matching.pointer("/metadata/name").and_then(Value::as_str) {
                    let _ = self
                        .client
                        .replace_namespaced_object(
                            "apps",
                            "ControllerRevision",
                            "controllerrevisions",
                            namespace,
                            name,
                            updated,
                        )
                        .await;
                }
            }
            return Ok(rev_hash);
        }

        let hash = compute_daemonset_template_hash(&p.template);
        self.create_daemonset_controller_revision(namespace, p, &hash, max_rev + 1)
            .await?;
        Ok(hash)
    }

    async fn create_daemonset_controller_revision(
        &self,
        namespace: &str,
        p: &DaemonSetParams<'_>,
        hash: &str,
        revision: i64,
    ) -> Result<(), ControllerError> {
        let cr_name = format!("{}-{hash}", p.name);
        let tpl_patch = normalize_daemonset_template_patch(&p.template);
        let mut cr_labels = p.template_labels.clone();
        if let Some(obj) = cr_labels.as_object_mut() {
            obj.insert("controller-revision-hash".to_string(), json!(hash));
            obj.insert("controller.kubernetes.io/hash".to_string(), json!(hash));
        }

        let new_cr = json!({
            "apiVersion": "apps/v1",
            "kind": "ControllerRevision",
            "metadata": {
                "name": cr_name,
                "namespace": namespace,
                "labels": cr_labels,
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "DaemonSet",
                    "name": p.name,
                    "uid": p.uid,
                    "controller": true,
                    "blockOwnerDeletion": true,
                }],
            },
            "data": {
                "spec": {
                    "template": tpl_patch,
                }
            },
            "revision": revision,
        });

        let _ = self
            .client
            .create_namespaced_object(
                "apps",
                "ControllerRevision",
                "controllerrevisions",
                namespace,
                new_cr,
            )
            .await;
        Ok(())
    }

    async fn sync_daemonset_pods(
        &self,
        namespace: &str,
        cfg: &DaemonSetConfig<'_>,
        template_spec: &Value,
        template_labels: &Value,
        matching_node_names: &BTreeSet<String>,
        owned_pods: &[Value],
    ) -> Result<(), ControllerError> {
        self.cleanup_unschedulable_node_pods(namespace, cfg.name, matching_node_names, owned_pods)
            .await;

        let any_pod_ready = owned_pods
            .iter()
            .any(|p| p.pointer("/metadata/deletionTimestamp").is_none() && super::is_pod_ready(p));
        let mut unavailable_nodes = matching_node_names
            .iter()
            .filter(|node_name| {
                !owned_pods.iter().any(|p| {
                    p.pointer("/metadata/deletionTimestamp").is_none()
                        && get_pod_node(p, cfg.name) == Some(node_name.as_str())
                        && super::is_pod_ready(p)
                })
            })
            .count();

        for node_name in matching_node_names {
            let (active_exists, failed_or_deleted) = self
                .sync_node_pods(
                    namespace,
                    cfg,
                    node_name,
                    template_spec,
                    owned_pods,
                    any_pod_ready,
                    &mut unavailable_nodes,
                )
                .await;

            if !active_exists {
                self.ensure_daemonset_pod(
                    namespace,
                    cfg,
                    node_name,
                    template_spec,
                    template_labels,
                    &failed_or_deleted,
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn cleanup_unschedulable_node_pods(
        &self,
        namespace: &str,
        ds_name: &str,
        matching_node_names: &BTreeSet<String>,
        owned_pods: &[Value],
    ) {
        for pod in owned_pods {
            let p_node = get_pod_node(pod, ds_name);
            let matches = p_node.is_some_and(|n| matching_node_names.contains(n));
            if !matches && let Some(pname) = pod.pointer("/metadata/name").and_then(Value::as_str) {
                let _ = self
                    .client
                    .delete_pod_options(namespace, pname, Some(0))
                    .await;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn sync_node_pods(
        &self,
        namespace: &str,
        cfg: &DaemonSetConfig<'_>,
        node_name: &str,
        template_spec: &Value,
        owned_pods: &[Value],
        any_pod_ready: bool,
        unavailable_nodes: &mut usize,
    ) -> (bool, Vec<String>) {
        let mut active_exists = false;
        let mut failed_or_deleted = Vec::new();

        for pod in owned_pods {
            if get_pod_node(pod, cfg.name) != Some(node_name) {
                continue;
            }
            let pname = pod
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let is_terminating = pod.pointer("/metadata/deletionTimestamp").is_some();
            let is_failed = pod.pointer("/status/phase").and_then(Value::as_str) == Some("Failed");

            if is_terminating || is_failed {
                failed_or_deleted.push(pname.to_string());
                let _ = self
                    .client
                    .delete_pod_options(namespace, pname, Some(0))
                    .await;
                continue;
            }

            if cfg.update_strategy != "RollingUpdate" {
                active_exists = true;
                continue;
            }
            let pod_rev = pod
                .pointer("/metadata/labels/controller-revision-hash")
                .and_then(Value::as_str);
            let pod_img = pod
                .pointer("/spec/containers/0/image")
                .and_then(Value::as_str);
            let tpl_img = template_spec
                .pointer("/containers/0/image")
                .and_then(Value::as_str);
            let rev_matches = pod_rev == Some(cfg.rev_hash) && pod_img == tpl_img;
            let pod_ready = super::is_pod_ready(pod);
            if rev_matches
                || (any_pod_ready && pod_ready && *unavailable_nodes >= cfg.max_unavailable)
            {
                active_exists = true;
                continue;
            }
            if pod_ready {
                *unavailable_nodes += 1;
            }
            failed_or_deleted.push(pname.to_string());
            let _ = self
                .client
                .delete_pod_options(namespace, pname, Some(0))
                .await;
        }

        (active_exists, failed_or_deleted)
    }

    async fn ensure_daemonset_pod(
        &self,
        namespace: &str,
        cfg: &DaemonSetConfig<'_>,
        node_name: &str,
        template_spec: &Value,
        template_labels: &Value,
        failed_or_deleted_names: &[String],
    ) -> Result<(), ControllerError> {
        let base_name = format!("{}-{node_name}", cfg.name);

        let mut pod_name = base_name.clone();
        if !failed_or_deleted_names.is_empty()
            || failed_or_deleted_names.iter().any(|n| n == &pod_name)
            || self
                .is_pod_terminating_or_failed(namespace, &pod_name)
                .await
        {
            pod_name = format!("{base_name}-{}", cfg.rev_hash);
            let mut counter = 1;
            while failed_or_deleted_names.iter().any(|n| n == &pod_name)
                || self
                    .is_pod_terminating_or_failed(namespace, &pod_name)
                    .await
            {
                pod_name = format!("{base_name}-{}-{counter}", cfg.rev_hash);
                counter += 1;
            }
        }

        if self.client.get_pod(namespace, &pod_name).await.is_ok() {
            return Ok(());
        }

        let mut pod_spec = template_spec.clone();
        pod_spec.as_object_mut().unwrap().remove("nodeName");
        pod_spec["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"] = json!({"nodeSelectorTerms":[{"matchFields":[{"key":"metadata.name","operator":"In","values":[node_name]}]}]});

        add_daemon_tolerations(&mut pod_spec);

        let mut pod_labels = template_labels.clone();
        if let Some(l_obj) = pod_labels.as_object_mut() {
            l_obj.insert(
                "daemonset.kubernetes.io/pod-name".to_string(),
                json!(pod_name),
            );
            l_obj.insert("controller-revision-hash".to_string(), json!(cfg.rev_hash));
            l_obj.insert(
                "controller.kubernetes.io/hash".to_string(),
                json!(cfg.rev_hash),
            );
            l_obj.insert("pod-template-hash".to_string(), json!(cfg.rev_hash));
            l_obj.insert(
                "pod-template-generation".to_string(),
                json!(cfg.generation.to_string()),
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
                    "kind": "DaemonSet",
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
        });

        let _ = self.client.create_pod(namespace, new_pod).await;
        Ok(())
    }

    async fn is_pod_terminating_or_failed(&self, namespace: &str, pod_name: &str) -> bool {
        if let Ok(pod) = self.client.get_pod(namespace, pod_name).await {
            let is_terminating = pod.pointer("/metadata/deletionTimestamp").is_some();
            let is_failed = pod.pointer("/status/phase").and_then(Value::as_str) == Some("Failed");
            is_terminating || is_failed
        } else {
            false
        }
    }
}

struct DaemonSetConfig<'a> {
    name: &'a str,
    uid: &'a str,
    generation: i64,
    rev_hash: &'a str,
    update_strategy: &'a str,
    max_unavailable: usize,
}

fn parse_max_unavailable(ds: &Value, total_nodes: usize) -> usize {
    let Some(val) = ds.pointer("/spec/updateStrategy/rollingUpdate/maxUnavailable") else {
        return 1;
    };
    if let Some(n) = val.as_u64() {
        return usize::try_from(n).unwrap_or(1).max(1);
    }
    if let Some(s) = val.as_str()
        && let Some(pct_str) = s.strip_suffix('%')
        && let Ok(pct) = pct_str.trim().parse::<usize>()
    {
        return (total_nodes.saturating_mul(pct).saturating_add(99) / 100).max(1);
    }
    1
}

fn filter_schedulable_nodes(raw_nodes: &[Value]) -> Vec<Value> {
    raw_nodes
        .iter()
        .filter(|node| node.pointer("/metadata/deletionTimestamp").is_none())
        .cloned()
        .collect()
}

fn find_matching_node_names(
    schedulable_nodes: &[Value],
    template_spec: &Value,
) -> BTreeSet<String> {
    schedulable_nodes
        .iter()
        .filter(|node| node_matches_daemonset(node, template_spec))
        .filter_map(|node| node.pointer("/metadata/name").and_then(Value::as_str))
        .map(ToString::to_string)
        .collect()
}

fn compute_daemonset_status(
    ds: &Value,
    deleting: bool,
    matching_node_names: &BTreeSet<String>,
    updated_pods: &[Value],
    name: &str,
    rev_hash: &str,
) -> Value {
    let desired_number_scheduled = if deleting {
        0
    } else {
        matching_node_names.len()
    };
    let mut current_number_scheduled = 0;
    let mut number_ready = 0;
    let mut updated_number_scheduled = 0;

    for node_name in matching_node_names {
        let node_pod = updated_pods.iter().find(|pod| {
            let is_not_deleting = pod.pointer("/metadata/deletionTimestamp").is_none();
            let matches_node = get_pod_node(pod, name) == Some(node_name.as_str());
            is_not_deleting && matches_node
        });

        if let Some(pod) = node_pod {
            current_number_scheduled += 1;
            let pod_rev = pod
                .pointer("/metadata/labels/controller-revision-hash")
                .and_then(Value::as_str);
            if pod_rev == Some(rev_hash) || rev_hash.is_empty() {
                updated_number_scheduled += 1;
            }
            if super::is_pod_ready(pod) {
                number_ready += 1;
            }
        }
    }

    let observed_generation = ds
        .pointer("/metadata/generation")
        .and_then(Value::as_i64)
        .unwrap_or(1);

    json!({
        "desiredNumberScheduled": desired_number_scheduled,
        "currentNumberScheduled": current_number_scheduled,
        "numberReady": number_ready,
        "numberAvailable": number_ready,
        "updatedNumberScheduled": updated_number_scheduled,
        "observedGeneration": observed_generation,
    })
}

fn add_daemon_tolerations(spec: &mut Value) {
    let mut required = vec![
        ("node.kubernetes.io/not-ready", "NoExecute"),
        ("node.kubernetes.io/unreachable", "NoExecute"),
        ("node.kubernetes.io/disk-pressure", "NoSchedule"),
        ("node.kubernetes.io/memory-pressure", "NoSchedule"),
        ("node.kubernetes.io/pid-pressure", "NoSchedule"),
        ("node.kubernetes.io/unschedulable", "NoSchedule"),
    ];
    if spec["hostNetwork"] == true {
        required.push(("node.kubernetes.io/network-unavailable", "NoSchedule"));
    }
    let mut tolerations = spec["tolerations"].as_array().cloned().unwrap_or_default();
    for (key, effect) in required {
        if !tolerations.iter().any(|t| {
            t["key"] == key
                && t["operator"] == "Exists"
                && (t["effect"] == effect || t.get("effect").is_none())
        }) {
            tolerations.push(json!({"key":key,"operator":"Exists","effect":effect}));
        }
    }
    spec["tolerations"] = Value::Array(tolerations);
}

fn get_pod_node<'a>(pod: &'a Value, _ds_name: &str) -> Option<&'a str> {
    pod.pointer("/spec/nodeName").and_then(Value::as_str).filter(|s| !s.is_empty())
        .or_else(|| pod.pointer("/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/0/matchFields/0/values/0").and_then(Value::as_str))
}

fn node_matches_daemonset(node: &Value, template_spec: &Value) -> bool {
    let node_labels = node.pointer("/metadata/labels").and_then(Value::as_object);
    let node_name = node
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");

    // 1. Check spec.template.spec.nodeSelector
    if let Some(selector) = template_spec.get("nodeSelector").and_then(Value::as_object) {
        for (k, v) in selector {
            let expected = v.as_str().unwrap_or("");
            if node_labels.and_then(|l| l.get(k)).and_then(Value::as_str) != Some(expected) {
                return false;
            }
        }
    }

    // 2. Check spec.template.spec.affinity.nodeAffinity or spec.template.spec.nodeAffinity
    let terms_opt = template_spec
        .pointer("/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms")
        .or_else(|| {
            template_spec.pointer(
                "/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms",
            )
        })
        .and_then(Value::as_array);

    if let Some(terms) = terms_opt
        && !terms.is_empty()
        && !terms
            .iter()
            .any(|term| term_matches_node(term, node_name, node_labels))
    {
        return false;
    }

    true
}

fn term_matches_node(
    term: &Value,
    node_name: &str,
    node_labels: Option<&serde_json::Map<String, Value>>,
) -> bool {
    // matchExpressions (AND within term)
    if let Some(exprs) = term.get("matchExpressions").and_then(Value::as_array) {
        for expr in exprs {
            let key = expr.get("key").and_then(Value::as_str).unwrap_or("");
            let op = expr.get("operator").and_then(Value::as_str).unwrap_or("In");
            let values: Vec<&str> = expr
                .get("values")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();

            let label_val = node_labels.and_then(|l| l.get(key)).and_then(Value::as_str);
            if !eval_node_operator(label_val, op, &values) {
                return false;
            }
        }
    }

    // matchFields (AND within term)
    if let Some(fields) = term.get("matchFields").and_then(Value::as_array) {
        for field in fields {
            let key = field.get("key").and_then(Value::as_str).unwrap_or("");
            let op = field
                .get("operator")
                .and_then(Value::as_str)
                .unwrap_or("In");
            let values: Vec<&str> = field
                .get("values")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();

            let field_val = match key {
                "metadata.name" => Some(node_name),
                _ => None,
            };
            if !eval_node_operator(field_val, op, &values) {
                return false;
            }
        }
    }

    true
}

fn eval_node_operator(actual: Option<&str>, op: &str, values: &[&str]) -> bool {
    match op {
        "In" => actual.is_some_and(|a| values.contains(&a)),
        "NotIn" => actual.is_none_or(|a| !values.contains(&a)),
        "Exists" => actual.is_some(),
        "DoesNotExist" => actual.is_none(),
        "Gt" => compare_node_int(actual, values.first(), |a, b| a > b),
        "Lt" => compare_node_int(actual, values.first(), |a, b| a < b),
        _ => false,
    }
}

fn compare_node_int(
    actual: Option<&str>,
    target: Option<&&str>,
    cmp: fn(i64, i64) -> bool,
) -> bool {
    let Some(a_str) = actual else { return false };
    let Some(&v_str) = target else { return false };
    let (Ok(a_int), Ok(v_int)) = (a_str.parse::<i64>(), v_str.parse::<i64>()) else {
        return false;
    };
    cmp(a_int, v_int)
}

struct DaemonSetParams<'a> {
    name: &'a str,
    uid: &'a str,
    generation: i64,
    deleting: bool,
    template: Value,
    template_labels: Value,
    template_spec: Value,
    selector_val: Value,
    update_strategy: String,
}

fn parse_daemonset_params(ds: &Value) -> Result<DaemonSetParams<'_>, ControllerError> {
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

    let generation = ds
        .pointer("/metadata/generation")
        .and_then(Value::as_i64)
        .unwrap_or(1);

    let deleting = ds
        .pointer("/metadata/deletionTimestamp")
        .and_then(Value::as_str)
        .is_some();

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

    let selector_val = ds
        .pointer("/spec/selector")
        .cloned()
        .unwrap_or_else(|| json!({ "matchLabels": template_labels }));

    let update_strategy = ds
        .pointer("/spec/updateStrategy/type")
        .and_then(Value::as_str)
        .unwrap_or("RollingUpdate")
        .to_string();

    Ok(DaemonSetParams {
        name,
        uid,
        generation,
        deleting,
        template,
        template_labels,
        template_spec,
        selector_val,
        update_strategy,
    })
}

fn strip_daemonset_owner_ref(rev: &mut Value, ds_name: &str, ds_uid: &str) {
    if let Some(owners_mut) = rev
        .pointer_mut("/metadata/ownerReferences")
        .and_then(Value::as_array_mut)
    {
        owners_mut.retain(|o| {
            let matches_kind = o.get("kind").and_then(Value::as_str) == Some("DaemonSet");
            let matches_uid =
                !ds_uid.is_empty() && o.get("uid").and_then(Value::as_str) == Some(ds_uid);
            let matches_name = o.get("name").and_then(Value::as_str) == Some(ds_name);
            let is_controller = o
                .get("controller")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            !(matches_kind && (matches_uid || matches_name) && is_controller)
        });
    }
}

fn add_daemonset_owner_ref(rev: &mut Value, ds_name: &str, ds_uid: &str) {
    let mut new_owners = rev
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    new_owners.push(json!({
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "name": ds_name,
        "uid": ds_uid,
        "controller": true,
        "blockOwnerDeletion": true
    }));
    if let Some(meta) = rev.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.insert("ownerReferences".to_string(), Value::Array(new_owners));
    }
}

fn compute_daemonset_template_hash(template: &Value) -> String {
    let clean = clean_template_for_comparison(template);
    let serialized = serde_json::to_string(&clean).unwrap_or_default();
    let mut hasher: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in serialized.as_bytes() {
        hasher ^= u64::from(*byte);
        hasher = hasher.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{:010x}", hasher & 0x00ff_ffff_ffff)
}

fn cr_matches_template(cr: &Value, current_template: &Value) -> bool {
    let Some(cr_tpl) = cr.pointer("/data/spec/template") else {
        return false;
    };
    clean_template_for_comparison(cr_tpl) == clean_template_for_comparison(current_template)
}

fn normalize_daemonset_template_patch(template: &Value) -> Value {
    let mut tpl_patch = if template.is_object() {
        template.clone()
    } else {
        json!({})
    };

    if let Some(obj) = tpl_patch.as_object_mut() {
        obj.insert("$patch".to_string(), json!("replace"));

        let meta = obj
            .entry("metadata".to_string())
            .or_insert_with(|| json!({}));
        if let Some(meta_obj) = meta.as_object_mut() {
            meta_obj
                .entry("creationTimestamp".to_string())
                .or_insert(Value::Null);

            if let Some(labels) = meta_obj.get_mut("labels").and_then(Value::as_object_mut) {
                labels.remove("controller-revision-hash");
                labels.remove("pod-template-hash");
                labels.remove("controller.kubernetes.io/hash");
                labels.remove("pod-template-generation");
            }
        }

        if let Some(spec) = obj.get_mut("spec").and_then(Value::as_object_mut) {
            normalize_container_resources(spec, "containers");
            normalize_container_resources(spec, "initContainers");
        }
    }

    tpl_patch
}

fn normalize_container_resources(spec: &mut serde_json::Map<String, Value>, key: &str) {
    if let Some(containers) = spec.get_mut(key).and_then(Value::as_array_mut) {
        for c in containers {
            if let Some(c_obj) = c.as_object_mut() {
                match c_obj.get_mut("resources") {
                    Some(res) if res.is_null() => *res = json!({}),
                    None => {
                        c_obj.insert("resources".to_string(), json!({}));
                    },
                    _ => {},
                }
            }
        }
    }
}

fn clean_template_for_comparison(val: &Value) -> Value {
    let mut clean = normalize_daemonset_template_patch(val);
    if let Some(obj) = clean.as_object_mut() {
        obj.remove("$patch");
    }
    clean
}

fn extract_cr_hash(cr: &Value, ds_name: &str) -> String {
    cr.pointer("/metadata/labels/controller-revision-hash")
        .or_else(|| cr.pointer("/metadata/labels/controller.kubernetes.io/hash"))
        .and_then(Value::as_str)
        .map_or_else(
            || {
                let full_name = cr
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                full_name
                    .strip_prefix(&format!("{ds_name}-"))
                    .unwrap_or("rev")
                    .to_string()
            },
            str::to_string,
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_max_unavailable_respects_int_and_percent() {
        let ds_default = json!({});
        assert_eq!(parse_max_unavailable(&ds_default, 2), 1);

        let ds_int = json!({
            "spec": { "updateStrategy": { "rollingUpdate": { "maxUnavailable": 2 } } }
        });
        assert_eq!(parse_max_unavailable(&ds_int, 4), 2);

        let ds_pct = json!({
            "spec": { "updateStrategy": { "rollingUpdate": { "maxUnavailable": "50%" } } }
        });
        assert_eq!(parse_max_unavailable(&ds_pct, 4), 2);
    }
}
