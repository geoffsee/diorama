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
        let mut child_job_name = format!("{name}-scheduled");
        if self
            .client
            .get_job(namespace, &child_job_name)
            .await
            .is_ok()
        {
            let mut counter = 1;
            loop {
                let candidate = format!("{name}-scheduled-{counter}");
                if self.client.get_job(namespace, &candidate).await.is_err() {
                    child_job_name = candidate;
                    break;
                }
                counter += 1;
            }
        }

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
            .pointer("/spec/suspend")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let concurrency_policy = cj
            .pointer("/spec/concurrencyPolicy")
            .and_then(Value::as_str)
            .unwrap_or("Allow");

        let job_list = self.client.list_jobs(namespace).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "jobs".to_string(),
                reason: e.to_string(),
            }
        })?;

        let all_jobs = job_list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let owned_jobs: Vec<Value> = all_jobs
            .into_iter()
            .filter(|j| {
                j.pointer("/metadata/ownerReferences")
                    .and_then(Value::as_array)
                    .is_some_and(|owners| {
                        owners.iter().any(|o| {
                            o.get("kind").and_then(Value::as_str) == Some("CronJob")
                                && (o.get("uid").and_then(Value::as_str) == Some(uid)
                                    || o.get("name").and_then(Value::as_str) == Some(name))
                        })
                    })
            })
            .collect();

        let mut active_jobs = collect_active_jobs(&owned_jobs);

        let mut scheduled_new_job = false;
        if !is_suspended {
            let should_schedule = if concurrency_policy == "Replace" {
                for jname in &active_jobs {
                    let _ = self.client.delete_job(namespace, jname).await;
                }
                active_jobs.clear();
                true
            } else {
                active_jobs.is_empty()
            };

            if should_schedule {
                let job_template = cj
                    .get("spec")
                    .and_then(|s| s.get("jobTemplate"))
                    .cloned()
                    .unwrap_or_else(
                        || json!({ "spec": { "template": { "spec": { "containers": [] } } } }),
                    );

                let child_job_name = self
                    .ensure_scheduled_job(namespace, name, uid, &job_template)
                    .await?;

                if !active_jobs.contains(&child_job_name) {
                    active_jobs.push(child_job_name);
                }
                scheduled_new_job = true;
            }
        }

        let now = diorama_apiserver::time::now_rfc3339();
        let updated_cj =
            update_cronjob_status(cj, namespace, &active_jobs, scheduled_new_job, &now);

        if updated_cj.get("status") == cj.get("status") {
            return Ok(updated_cj);
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

fn collect_active_jobs(owned_jobs: &[Value]) -> Vec<String> {
    owned_jobs
        .iter()
        .filter(|job| !is_job_finished(job) && job.pointer("/metadata/deletionTimestamp").is_none())
        .filter_map(|job| job.pointer("/metadata/name").and_then(Value::as_str))
        .map(ToString::to_string)
        .collect()
}

fn update_cronjob_status(
    cj: &Value,
    namespace: &str,
    active_jobs: &[String],
    scheduled_new_job: bool,
    now: &str,
) -> Value {
    let active_val: Vec<Value> = active_jobs
        .iter()
        .map(|jname| {
            json!({
                "apiVersion": "batch/v1",
                "kind": "Job",
                "name": jname,
                "namespace": namespace
            })
        })
        .collect();

    let mut updated = cj.clone();
    if let Some(status) = updated.get_mut("status").and_then(Value::as_object_mut) {
        if scheduled_new_job || !status.contains_key("lastScheduleTime") {
            status.insert("lastScheduleTime".to_string(), json!(now));
        }
        status.insert("active".to_string(), json!(active_val));
    } else if let Some(cj_obj) = updated.as_object_mut() {
        cj_obj.insert(
            "status".to_string(),
            json!({
                "lastScheduleTime": now,
                "active": active_val
            }),
        );
    }
    updated
}

fn is_job_finished(job: &Value) -> bool {
    let Some(conds) = job.pointer("/status/conditions").and_then(Value::as_array) else {
        return false;
    };
    conds.iter().any(|c| {
        matches!(
            c.get("type").and_then(Value::as_str),
            Some("Complete" | "Failed")
        ) && c.get("status").and_then(Value::as_str) == Some("True")
    })
}
