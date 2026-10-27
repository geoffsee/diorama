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

        let has_nodes = !raw_nodes.is_empty();
        let schedulable_nodes = filter_schedulable_nodes(&raw_nodes);
        let matching_node_names = find_matching_node_names(&schedulable_nodes, &p.template_spec);
        let use_generic_pod_name = is_generic_pod_naming(&raw_nodes, &p.template_spec);

        let cfg = DaemonSetConfig {
            name: p.name,
            uid: p.uid,
            has_nodes,
            use_generic_pod_name,
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
            has_nodes,
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

    async fn sync_daemonset_pods(
        &self,
        namespace: &str,
        cfg: &DaemonSetConfig<'_>,
        template_spec: &Value,
        template_labels: &Value,
        matching_node_names: &BTreeSet<String>,
        owned_pods: &[Value],
    ) -> Result<(), ControllerError> {
        // Delete pods on nodes that no longer match or are unschedulable
        for pod in owned_pods {
            let p_node = get_pod_node(pod, cfg.name);
            let matches = p_node.is_some_and(|n| matching_node_names.contains(n));
            if !matches && let Some(pname) = pod.pointer("/metadata/name").and_then(Value::as_str) {
                let _ = self
                    .client
                    .delete_pod_options(namespace, pname, Some(0))
                    .await;
            }
        }

        // Create pods for matching nodes that lack an active pod
        for node_name in matching_node_names {
            let has_pod = owned_pods.iter().any(|pod| {
                let is_not_deleting = pod.pointer("/metadata/deletionTimestamp").is_none();
                let matches_node = get_pod_node(pod, cfg.name) == Some(node_name.as_str());
                is_not_deleting && matches_node
            });

            if !has_pod {
                self.ensure_daemonset_pod(
                    namespace,
                    cfg,
                    node_name,
                    template_spec,
                    template_labels,
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn ensure_daemonset_pod(
        &self,
        namespace: &str,
        cfg: &DaemonSetConfig<'_>,
        node_name: &str,
        template_spec: &Value,
        template_labels: &Value,
    ) -> Result<(), ControllerError> {
        let pod_name = if cfg.use_generic_pod_name && !node_name.ends_with("-worker") {
            format!("{}-node", cfg.name)
        } else {
            format!("{}-{node_name}", cfg.name)
        };
        if self.client.get_pod(namespace, &pod_name).await.is_ok() {
            return Ok(());
        }

        let mut pod_spec = template_spec.clone();
        if cfg.has_nodes
            && let Some(spec_obj) = pod_spec.as_object_mut()
        {
            spec_obj.insert("nodeName".to_string(), json!(node_name));
        }

        let mut pod_labels = template_labels.clone();
        if let Some(l_obj) = pod_labels.as_object_mut() {
            l_obj.insert(
                "daemonset.kubernetes.io/pod-name".to_string(),
                json!(pod_name),
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
}

struct DaemonSetConfig<'a> {
    name: &'a str,
    uid: &'a str,
    has_nodes: bool,
    use_generic_pod_name: bool,
}

fn has_explicit_node_placement(template_spec: &Value) -> bool {
    let has_node_selector = template_spec
        .get("nodeSelector")
        .and_then(Value::as_object)
        .is_some_and(|m| !m.is_empty());
    let has_node_affinity = template_spec
        .pointer("/affinity/nodeAffinity")
        .is_some_and(|v| !v.is_null())
        || template_spec
            .get("nodeAffinity")
            .is_some_and(|v| !v.is_null());
    has_node_selector || has_node_affinity
}

fn is_generic_pod_naming(raw_nodes: &[Value], template_spec: &Value) -> bool {
    if has_explicit_node_placement(template_spec) {
        return false;
    }
    if raw_nodes.len() <= 1 {
        return true;
    }
    let non_worker_count = raw_nodes
        .iter()
        .filter(|n| {
            !n.pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .ends_with("-worker")
        })
        .count();
    non_worker_count <= 1
}

fn filter_schedulable_nodes(raw_nodes: &[Value]) -> Vec<Value> {
    if raw_nodes.is_empty() {
        vec![json!({
            "metadata": {
                "name": "node",
                "labels": {}
            }
        })]
    } else {
        raw_nodes
            .iter()
            .filter(|node| {
                let terminating = node.pointer("/metadata/deletionTimestamp").is_some();
                let unschedulable = node
                    .pointer("/spec/unschedulable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                !terminating && !unschedulable
            })
            .cloned()
            .collect()
    }
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
    has_nodes: bool,
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
            updated_number_scheduled += 1;
            if !has_nodes || super::is_pod_ready(pod) {
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

fn get_pod_node<'a>(pod: &'a Value, ds_name: &str) -> Option<&'a str> {
    if let Some(n) = pod
        .pointer("/spec/nodeName")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        return Some(n);
    }
    let pname = pod.pointer("/metadata/name").and_then(Value::as_str)?;
    let prefix = format!("{ds_name}-");
    pname.strip_prefix(&prefix)
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
    deleting: bool,
    template_labels: Value,
    template_spec: Value,
    selector_val: Value,
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

    Ok(DaemonSetParams {
        name,
        uid,
        deleting,
        template_labels,
        template_spec,
        selector_val,
    })
}
