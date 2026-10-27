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
        avoid_names: &[String],
    ) -> Result<String, ControllerError> {
        let child_job_name = self
            .choose_candidate_job_name(namespace, name, avoid_names)
            .await;

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

    async fn choose_candidate_job_name(
        &self,
        namespace: &str,
        name: &str,
        avoid_names: &[String],
    ) -> String {
        let default_name = format!("{name}-scheduled");
        if avoid_names.is_empty() && self.client.get_job(namespace, &default_name).await.is_err() {
            return default_name;
        }

        let start_counter = avoid_names
            .iter()
            .filter_map(|n| parse_job_suffix(n, name))
            .max()
            .map_or(1, |m| m + 1);

        let mut counter = start_counter;
        loop {
            let candidate = format!("{name}-scheduled-{counter}");
            if !avoid_names.contains(&candidate)
                && self.client.get_job(namespace, &candidate).await.is_err()
            {
                return candidate;
            }
            counter += 1;
        }
    }

    async fn should_schedule_job(
        &self,
        namespace: &str,
        cj: &Value,
        concurrency_policy: &str,
        active_jobs: &mut Vec<String>,
        all_pods: &[Value],
        avoid_names: &mut Vec<String>,
    ) -> bool {
        match concurrency_policy {
            "Replace" => {
                self.handle_replace_policy(namespace, cj, active_jobs, all_pods, avoid_names)
                    .await
            },
            "Allow" => {
                active_jobs.is_empty()
                    || (active_jobs.len() < 2 && cj.pointer("/status/lastScheduleTime").is_some())
            },
            _ => active_jobs.is_empty(),
        }
    }

    async fn handle_replace_policy(
        &self,
        namespace: &str,
        cj: &Value,
        active_jobs: &mut Vec<String>,
        all_pods: &[Value],
        avoid_names: &mut Vec<String>,
    ) -> bool {
        if active_jobs.is_empty() {
            return true;
        }
        if !should_replace_active_jobs(cj, active_jobs, all_pods) {
            return false;
        }
        for jname in active_jobs.iter() {
            delete_active_job_pods(&self.client, namespace, jname, all_pods).await;
            let _ = self.client.delete_job(namespace, jname).await;
        }
        avoid_names.extend(active_jobs.clone());
        active_jobs.clear();
        true
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

        let all_jobs = self
            .client
            .list_jobs(namespace)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: "jobs".to_string(),
                reason: e.to_string(),
            })?
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let all_pods = self
            .client
            .list_pods(namespace)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: "pods".to_string(),
                reason: e.to_string(),
            })?
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let owned_jobs = filter_owned_jobs(all_jobs, uid, name);
        let mut active_jobs = collect_active_jobs(&owned_jobs);
        let mut scheduled_new_job = false;
        let mut avoid_names = Vec::new();

        if !is_suspended
            && self
                .should_schedule_job(
                    namespace,
                    cj,
                    concurrency_policy,
                    &mut active_jobs,
                    &all_pods,
                    &mut avoid_names,
                )
                .await
        {
            avoid_names.extend(active_jobs.clone());
            let job_template = cj
                .get("spec")
                .and_then(|s| s.get("jobTemplate"))
                .cloned()
                .unwrap_or_else(
                    || json!({ "spec": { "template": { "spec": { "containers": [] } } } }),
                );

            let child_job_name = self
                .ensure_scheduled_job(namespace, name, uid, &job_template, &avoid_names)
                .await?;

            if !active_jobs.contains(&child_job_name) {
                active_jobs.push(child_job_name);
            }
            scheduled_new_job = true;
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

fn filter_owned_jobs(all_jobs: Vec<Value>, uid: &str, name: &str) -> Vec<Value> {
    all_jobs
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
        .collect()
}

fn parse_job_suffix(job_name: &str, cronjob_name: &str) -> Option<usize> {
    let prefix = format!("{cronjob_name}-scheduled");
    if job_name == prefix {
        Some(0)
    } else if let Some(rest) = job_name.strip_prefix(&format!("{prefix}-")) {
        rest.strip_prefix('r').unwrap_or(rest).parse::<usize>().ok()
    } else {
        None
    }
}

async fn delete_active_job_pods(
    client: &KubernetesApiClient,
    namespace: &str,
    job_name: &str,
    pods: &[Value],
) {
    for pod in pods {
        if is_pod_owned_by_job(pod, job_name)
            && let Some(pod_name) = pod.pointer("/metadata/name").and_then(Value::as_str)
        {
            let _ = client.delete_pod(namespace, pod_name).await;
        }
    }
}

fn is_pod_owned_by_job(pod: &Value, job_name: &str) -> bool {
    pod.pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .is_some_and(|owners| {
            owners.iter().any(|o| {
                o.get("kind").and_then(Value::as_str) == Some("Job")
                    && o.get("name").and_then(Value::as_str) == Some(job_name)
            })
        })
        || pod
            .pointer("/metadata/labels/job-name")
            .and_then(Value::as_str)
            == Some(job_name)
        || pod
            .pointer("/metadata/labels/batch.kubernetes.io/job-name")
            .and_then(Value::as_str)
            == Some(job_name)
}

fn should_replace_active_jobs(cj: &Value, active_jobs: &[String], pods: &[Value]) -> bool {
    if active_jobs.is_empty() {
        return false;
    }
    let Some(last_sched) = cj
        .pointer("/status/lastScheduleTime")
        .and_then(Value::as_str)
    else {
        return false;
    };
    let now = diorama_apiserver::time::now_rfc3339();
    let has_pods = pods.iter().any(|p| {
        active_jobs
            .iter()
            .any(|jname| is_pod_owned_by_job(p, jname))
    });
    let age_ok = diorama_apiserver::time::parse_rfc3339_seconds(last_sched)
        .is_some_and(|ts| diorama_apiserver::time::now_unix().saturating_sub(ts) >= 2);
    age_ok || (has_pods && last_sched != now)
}
