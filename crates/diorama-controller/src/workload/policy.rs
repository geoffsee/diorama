//! Status reconcilers for `PodDisruptionBudget` and `ResourceQuota`.

use std::sync::Arc;

use diorama_apiserver::client::KubernetesApiClient;
use diorama_apiserver::{pdb, quota};
use serde_json::Value;

use super::ReconcileOutcome;
use crate::error::ControllerError;

fn items(list: Result<Value, diorama_apiserver::ApiserverError>) -> Vec<Value> {
    list.ok()
        .and_then(|l| l.get("items").and_then(Value::as_array).cloned())
        .unwrap_or_default()
}

/// Strips volatile condition timestamps so unchanged statuses are not rewritten.
fn comparable(status: Option<&Value>) -> Value {
    let mut status = status.cloned().unwrap_or(Value::Null);
    if let Some(conds) = status.get_mut("conditions").and_then(Value::as_array_mut) {
        for c in conds {
            if let Some(obj) = c.as_object_mut() {
                obj.remove("lastTransitionTime");
            }
        }
    }
    status
}

/// Keeps `PodDisruptionBudget.status` in line with the pods it selects.
#[derive(Clone, Debug)]
pub struct DisruptionReconciler {
    client: Arc<KubernetesApiClient>,
}

impl DisruptionReconciler {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    pub async fn reconcile_all(
        &self,
        namespace: &str,
    ) -> Result<ReconcileOutcome, ControllerError> {
        let pdbs = items(
            self.client
                .list_namespaced_objects(
                    "policy",
                    "PodDisruptionBudgetList",
                    "poddisruptionbudgets",
                    namespace,
                )
                .await,
        );
        let mut outcome = ReconcileOutcome::default();
        if pdbs.is_empty() {
            return Ok(outcome);
        }
        let pods = items(self.client.list_pods(namespace).await);
        let now = diorama_apiserver::time::now_rfc3339();
        for mut budget in pdbs {
            if budget
                .pointer("/metadata/deletionTimestamp")
                .and_then(Value::as_str)
                .is_some()
            {
                continue;
            }
            let Some(name) = budget
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            let mut counts = pdb::compute_counts(&budget, &pods);
            // Evicted pods stay "disrupted" until the kubelet removes them.
            let disrupted = prune_disrupted(&mut budget, &pods);
            counts.disruptions_allowed = (counts.disruptions_allowed - disrupted).max(0);
            let status = pdb::status_value(&budget, counts, &now);
            if comparable(budget.get("status")) == comparable(Some(&status)) {
                continue;
            }
            budget["status"] = status;
            match self
                .client
                .replace_namespaced_object(
                    "policy",
                    "PodDisruptionBudget",
                    "poddisruptionbudgets",
                    namespace,
                    &name,
                    budget,
                )
                .await
            {
                Ok(_) => outcome.reconciled += 1,
                Err(e) => outcome.errors.push(format!("pdb {namespace}/{name}: {e}")),
            }
        }
        Ok(outcome)
    }
}

/// Drops `disruptedPods` entries whose pod is gone or already terminating and
/// returns how many still-healthy disrupted pods remain.
fn prune_disrupted(budget: &mut Value, pods: &[Value]) -> i64 {
    let Some(map) = budget
        .pointer_mut("/status/disruptedPods")
        .and_then(Value::as_object_mut)
    else {
        return 0;
    };
    map.retain(|name, _| {
        pods.iter().any(|p| {
            p.pointer("/metadata/name").and_then(Value::as_str) == Some(name.as_str())
                && pdb::is_healthy(p)
        })
    });
    i64::try_from(map.len()).unwrap_or(0)
}

/// Publishes `ResourceQuota.status.hard` and `status.used`.
#[derive(Clone, Debug)]
pub struct ResourceQuotaReconciler {
    client: Arc<KubernetesApiClient>,
}

impl ResourceQuotaReconciler {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    pub async fn reconcile_all(
        &self,
        namespace: &str,
    ) -> Result<ReconcileOutcome, ControllerError> {
        let quotas = quota::list_counted(
            &self.client,
            "",
            "ResourceQuotaList",
            "resourcequotas",
            namespace,
        )
        .await;
        let mut outcome = ReconcileOutcome::default();
        for mut q in quotas {
            let Some(name) = q
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            let totals = quota::compute_totals(&self.client, &q, namespace).await;
            let status = quota::status_from_usage(&q, &totals);
            if q.get("status") == Some(&status) {
                continue;
            }
            q["status"] = status;
            match self
                .client
                .replace_namespaced_object(
                    "",
                    "ResourceQuota",
                    "resourcequotas",
                    namespace,
                    &name,
                    q,
                )
                .await
            {
                Ok(_) => outcome.reconciled += 1,
                Err(e) => outcome
                    .errors
                    .push(format!("quota {namespace}/{name}: {e}")),
            }
        }
        Ok(outcome)
    }
}
