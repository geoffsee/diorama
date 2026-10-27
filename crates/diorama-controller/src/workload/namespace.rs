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

        if !pods.is_empty() {
            for pod in &pods {
                if let Some(pname) = pod.pointer("/metadata/name").and_then(Value::as_str) {
                    let _ = self.client.delete_pod(name, pname).await;
                }
            }

            // Verify if pods are still terminating
            if let Ok(updated_list) = self.client.list_pods(name).await
                && let Some(remaining) = updated_list.get("items").and_then(Value::as_array)
                && !remaining.is_empty()
            {
                return Ok(true);
            }
        }

        // Once no pods remain in the terminating namespace, delete the namespace from storage
        self.client.delete_namespace(name).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: format!("namespaces/{name}"),
                reason: e.to_string(),
            }
        })?;

        Ok(true)
    }
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
}
