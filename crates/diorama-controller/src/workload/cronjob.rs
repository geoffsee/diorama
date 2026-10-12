use std::sync::Arc;

use diorama_apiserver::client::KubernetesApiClient;
use serde_json::{Value, json};

use crate::error::ControllerError;
use crate::workload::ReconcileOutcome;

#[derive(Clone, Debug)]
pub struct CronJobReconciler {
    client: Arc<KubernetesApiClient>,
}

impl CronJobReconciler {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    /// Reconciles all `CronJobs` in the specified namespace.
    pub async fn reconcile_all(
        &self,
        namespace: &str,
    ) -> Result<ReconcileOutcome, ControllerError> {
        let list = self.client.list_cronjobs(namespace).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "cronjobs".to_string(),
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
        for cj in items {
            match self.reconcile_cronjob(namespace, &cj).await {
                Ok(_) => count += 1,
                Err(err) => errors.push(err.to_string()),
            }
        }

        Ok(ReconcileOutcome {
            reconciled: count,
            errors,
        })
    }

    async fn ensure_scheduled_job(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        job_template: &Value,
    ) -> Result<String, ControllerError> {
        let child_job_name = format!("{name}-scheduled");

        if self
            .client
            .get_job(namespace, &child_job_name)
            .await
            .is_err()
        {
            let mut job_spec = job_template
                .get("spec")
                .cloned()
                .unwrap_or_else(|| json!({}));
            if !job_spec.is_object() {
                job_spec = json!({
                    "template": {
                        "spec": {
                            "restartPolicy": "Never",
                            "containers": []
                        }
                    }
                });
            }

            let new_job = json!({
                "apiVersion": "batch/v1",
                "kind": "Job",
                "metadata": {
                    "name": child_job_name,
                    "namespace": namespace,
                    "ownerReferences": [{
                        "apiVersion": "batch/v1",
                        "kind": "CronJob",
                        "name": name,
                        "uid": uid,
                        "controller": true,
                        "blockOwnerDeletion": true
                    }]
                },
                "spec": job_spec
            });

            self.client
                .create_job(namespace, new_job)
                .await
                .map_err(|e| ControllerError::ReconciliationFailed {
                    resource: format!("jobs/{child_job_name}"),
                    reason: e.to_string(),
                })?;
        }

        Ok(child_job_name)
    }

    /// Reconciles a single `CronJob` by scheduling a child Job when active.
    pub async fn reconcile_cronjob(
        &self,
        namespace: &str,
        cj: &Value,
    ) -> Result<Value, ControllerError> {
        let name = cj
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ControllerError::InvalidConfiguration {
                field: "metadata.name".to_string(),
                reason: "CronJob missing metadata.name".to_string(),
            })?;

        let uid = cj
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let is_suspended = cj
            .get("spec")
            .and_then(|s| s.get("suspend"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if is_suspended {
            return Ok(cj.clone());
        }

        let job_template = cj
            .get("spec")
            .and_then(|s| s.get("jobTemplate"))
            .cloned()
            .unwrap_or_else(|| json!({ "spec": { "template": { "spec": { "containers": [] } } } }));

        let child_job_name = self
            .ensure_scheduled_job(namespace, name, uid, &job_template)
            .await?;

        let mut updated_cj = cj.clone();
        let active_val = json!([{
            "apiVersion": "batch/v1",
            "kind": "Job",
            "name": child_job_name,
            "namespace": namespace
        }]);

        if let Some(status) = updated_cj.get_mut("status").and_then(Value::as_object_mut) {
            status.insert(
                "lastScheduleTime".to_string(),
                json!("2026-09-30T00:00:00Z"),
            );
            status.insert("active".to_string(), active_val);
        } else if let Some(cj_obj) = updated_cj.as_object_mut() {
            cj_obj.insert(
                "status".to_string(),
                json!({
                    "lastScheduleTime": "2026-09-30T00:00:00Z",
                    "active": active_val
                }),
            );
        }

        self.client
            .update_cronjob(namespace, name, updated_cj)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("cronjobs/{name}"),
                reason: e.to_string(),
            })
    }
}
