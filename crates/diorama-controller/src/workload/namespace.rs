use std::sync::Arc;

use diorama_apiserver::client::KubernetesApiClient;
use serde_json::Value;

use crate::error::ControllerError;
use crate::workload::ReconcileOutcome;

/// Reconciler for namespace lifecycle and ordered pod cleanup during namespace termination.
///
/// When a `Namespace` has `deletionTimestamp` or `status.phase == "Terminating"`,
/// this controller deletes all pods residing in that namespace in an orderly fashion.
/// Once all pods are eliminated, it completes namespace finalization and deletes the namespace
/// resource from persistent storage.
#[derive(Clone, Debug)]
pub struct NamespaceReconciler {
    client: Arc<KubernetesApiClient>,
}

impl NamespaceReconciler {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    /// Reconciles all namespaces in the cluster, processing terminating ones.
    pub async fn reconcile_all(&self) -> Result<ReconcileOutcome, ControllerError> {
        let list = self.client.list_namespaces().await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "namespaces".to_string(),
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
        for ns in items {
            match self.reconcile_namespace(&ns).await {
                Ok(true) => count += 1,
                Ok(false) => {},
                Err(err) => errors.push(err.to_string()),
            }
        }

        Ok(ReconcileOutcome {
            reconciled: count,
            errors,
        })
    }

    /// Reconciles a single `Namespace`. Returns `Ok(true)` if action was taken,
    /// or `Ok(false)` if the namespace is active.
    pub async fn reconcile_namespace(&self, ns: &Value) -> Result<bool, ControllerError> {
        let name = ns
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .ok_or_else(|| ControllerError::InvalidConfiguration {
                field: "metadata.name".to_string(),
                reason: "Namespace missing metadata.name".to_string(),
            })?;

        let is_terminating = ns.pointer("/metadata/deletionTimestamp").is_some()
            || ns.pointer("/status/phase").and_then(Value::as_str) == Some("Terminating");

        if !is_terminating {
            return Ok(false);
        }

        let pod_list = self.client.list_pods(name).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "pods".to_string(),
                reason: e.to_string(),
            }
        })?;

        let pods = pod_list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        if pods.is_empty() {
            return finalize_namespace(&self.client, name).await;
        }

        for pod in &pods {
            if pod.pointer("/metadata/deletionTimestamp").is_none()
                && let Some(pname) = pod.pointer("/metadata/name").and_then(Value::as_str)
            {
                let _ = self.client.delete_pod(name, pname).await;
            }
        }

        let updated_pods = self
            .client
            .list_pods(name)
            .await
            .ok()
            .and_then(|l| l.get("items").and_then(Value::as_array).cloned())
            .unwrap_or_default();

        if updated_pods.is_empty() {
            return finalize_namespace(&self.client, name).await;
        }

        self.update_terminating_status(name, ns, &updated_pods)
            .await?;
        Ok(true)
    }

    async fn update_terminating_status(
        &self,
        name: &str,
        ns: &Value,
        remaining_pods: &[Value],
    ) -> Result<(), ControllerError> {
        let has_finalizers = remaining_pods.iter().any(|p| {
            p.pointer("/metadata/finalizers")
                .and_then(Value::as_array)
                .is_some_and(|f| !f.is_empty())
        });

        let now = diorama_apiserver::time::now_rfc3339();
        let conditions = build_termination_conditions(&now, remaining_pods.len(), has_finalizers);

        let mut current_ns = self
            .client
            .get_namespace(name)
            .await
            .unwrap_or_else(|_| ns.clone());
        let mut status = current_ns
            .get("status")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        if let Some(status_obj) = status.as_object_mut() {
            status_obj.insert("phase".to_string(), serde_json::json!("Terminating"));
            status_obj.insert("conditions".to_string(), serde_json::json!(conditions));
        }
        current_ns["status"] = status;

        let _ = self
            .client
            .replace_cluster_object("", "Namespace", "namespaces", name, current_ns)
            .await;
        Ok(())
    }
}

fn build_termination_conditions(
    now: &str,
    remaining_count: usize,
    has_finalizers: bool,
) -> Vec<Value> {
    let (content_status, content_reason, content_msg) = if remaining_count > 0 {
        (
            "True",
            "SomeResourcesRemain",
            format!("Some resources are remaining: pods. has {remaining_count} resource instances"),
        )
    } else {
        (
            "False",
            "ContentRemoved",
            "All content successfully removed".to_string(),
        )
    };

    let (fin_status, fin_reason, fin_msg) = if has_finalizers {
        (
            "True",
            "SomeFinalizersRemain",
            "Some content in the namespace has finalizers remaining".to_string(),
        )
    } else {
        (
            "False",
            "ContentHasNoFinalizers",
            "All content-preserving finalizers finished".to_string(),
        )
    };

    vec![
        serde_json::json!({
            "type": "NamespaceDeletionDiscoveryFailure",
            "status": "False",
            "lastTransitionTime": now,
            "reason": "ResourcesDiscovered",
            "message": "All resources successfully discovered"
        }),
        serde_json::json!({
            "type": "NamespaceDeletionGroupVersionParsingFailure",
            "status": "False",
            "lastTransitionTime": now,
            "reason": "ParsedGroupVersions",
            "message": "All legacy kube types successfully parsed"
        }),
        serde_json::json!({
            "type": "NamespaceDeletionContentFailure",
            "status": "False",
            "lastTransitionTime": now,
            "reason": "ContentDeleted",
            "message": "All content successfully deleted, may be waiting on finalization"
        }),
        serde_json::json!({
            "type": "NamespaceContentRemaining",
            "status": content_status,
            "lastTransitionTime": now,
            "reason": content_reason,
            "message": content_msg
        }),
        serde_json::json!({
            "type": "NamespaceFinalizersRemaining",
            "status": fin_status,
            "lastTransitionTime": now,
            "reason": fin_reason,
            "message": fin_msg
        }),
    ]
}

fn strip_namespace_finalizers(ns: &mut Value) -> bool {
    let mut modified = false;
    if let Some(spec) = ns.get_mut("spec").and_then(Value::as_object_mut)
        && spec.contains_key("finalizers")
    {
        spec.remove("finalizers");
        modified = true;
    }
    if let Some(meta) = ns.get_mut("metadata").and_then(Value::as_object_mut)
        && meta.contains_key("finalizers")
    {
        meta.remove("finalizers");
        modified = true;
    }
    modified
}

async fn finalize_namespace(
    client: &KubernetesApiClient,
    name: &str,
) -> Result<bool, ControllerError> {
    if let Ok(mut current) = client.get_namespace(name).await
        && strip_namespace_finalizers(&mut current)
    {
        let _ = client
            .replace_cluster_object("", "Namespace", "namespaces", name, current)
            .await;
    }
    client
        .delete_namespace(name)
        .await
        .map_err(|e| ControllerError::ReconciliationFailed {
            resource: format!("namespaces/{name}"),
            reason: e.to_string(),
        })?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_namespace_is_terminating_check() {
        let active = json!({
            "metadata": { "name": "active-ns" },
            "status": { "phase": "Active" }
        });
        assert!(active.pointer("/metadata/deletionTimestamp").is_none());
        assert_ne!(
            active.pointer("/status/phase").and_then(Value::as_str),
            Some("Terminating")
        );

        let terminating_ts = json!({
            "metadata": {
                "name": "term-ns-1",
                "deletionTimestamp": "2026-10-27T00:00:00Z"
            },
            "status": { "phase": "Active" }
        });
        assert!(
            terminating_ts
                .pointer("/metadata/deletionTimestamp")
                .is_some()
        );

        let terminating_phase = json!({
            "metadata": { "name": "term-ns-2" },
            "status": { "phase": "Terminating" }
        });
        assert_eq!(
            terminating_phase
                .pointer("/status/phase")
                .and_then(Value::as_str),
            Some("Terminating")
        );
    }

    #[test]
    fn test_build_termination_conditions() {
        let conds_remaining = build_termination_conditions("2026-10-27T00:00:00Z", 2, true);
        assert_eq!(conds_remaining.len(), 5);
        let content_cond = conds_remaining
            .iter()
            .find(|c| c.get("type").and_then(Value::as_str) == Some("NamespaceContentRemaining"))
            .unwrap();
        assert_eq!(content_cond["status"], "True");
        assert_eq!(content_cond["reason"], "SomeResourcesRemain");
        let fin_cond = conds_remaining
            .iter()
            .find(|c| c.get("type").and_then(Value::as_str) == Some("NamespaceFinalizersRemaining"))
            .unwrap();
        assert_eq!(fin_cond["status"], "True");
        assert_eq!(fin_cond["reason"], "SomeFinalizersRemain");

        let conds_empty = build_termination_conditions("2026-10-27T00:00:00Z", 0, false);
        let content_empty = conds_empty
            .iter()
            .find(|c| c.get("type").and_then(Value::as_str) == Some("NamespaceContentRemaining"))
            .unwrap();
        assert_eq!(content_empty["status"], "False");
        assert_eq!(content_empty["reason"], "ContentRemoved");
        let fin_empty = conds_empty
            .iter()
            .find(|c| c.get("type").and_then(Value::as_str) == Some("NamespaceFinalizersRemaining"))
            .unwrap();
        assert_eq!(fin_empty["status"], "False");
        assert_eq!(fin_empty["reason"], "ContentHasNoFinalizers");
    }

    #[test]
    fn test_strip_namespace_finalizers() {
        let mut ns = json!({
            "spec": { "finalizers": ["kubernetes"] },
            "metadata": { "finalizers": ["test-finalizer"] }
        });
        assert!(strip_namespace_finalizers(&mut ns));
        assert!(ns.pointer("/spec/finalizers").is_none());
        assert!(ns.pointer("/metadata/finalizers").is_none());
        assert!(!strip_namespace_finalizers(&mut ns));
    }
}
