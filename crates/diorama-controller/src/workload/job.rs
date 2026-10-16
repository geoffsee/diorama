use std::collections::BTreeSet;
use std::sync::Arc;

use diorama_apiserver::client::KubernetesApiClient;
use serde_json::{Value, json};

use crate::error::ControllerError;
use crate::workload::ReconcileOutcome;

#[derive(Clone, Debug)]
pub struct JobReconciler {
    client: Arc<KubernetesApiClient>,
}

impl JobReconciler {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    /// Reconciles all Jobs in the specified namespace.
    pub async fn reconcile_all(
        &self,
        namespace: &str,
    ) -> Result<ReconcileOutcome, ControllerError> {
        let list = self.client.list_jobs(namespace).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "jobs".to_string(),
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
        for job in items {
            match self.reconcile_job(namespace, &job).await {
                Ok(_) => count += 1,
                Err(err) => errors.push(err.to_string()),
            }
        }

        Ok(ReconcileOutcome {
            reconciled: count,
            errors,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_job_pod(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        pod_name: &str,
        completion_index: Option<usize>,
        template_labels: &Value,
        template_annotations: &Value,
        template_spec: &Value,
    ) -> Result<(), ControllerError> {
        let mut labels = template_labels.clone();
        let mut annotations = template_annotations.clone();
        let mut spec = template_spec.clone();

        if let Some(idx) = completion_index {
            let idx_str = idx.to_string();
            if let Some(obj) = labels.as_object_mut() {
                obj.insert(
                    "batch.kubernetes.io/job-completion-index".to_string(),
                    json!(idx_str),
                );
            }
            if let Some(obj) = annotations.as_object_mut() {
                obj.insert(
                    "batch.kubernetes.io/job-completion-index".to_string(),
                    json!(idx_str),
                );
            }
            inject_completion_index_env(&mut spec, &idx_str);
            if let Some(spec_obj) = spec.as_object_mut() {
                spec_obj
                    .entry("hostname".to_string())
                    .or_insert_with(|| json!(format!("{name}-{idx}")));
            }
        }

        let new_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": pod_name,
                "namespace": namespace,
                "labels": labels,
                "annotations": annotations,
                "ownerReferences": [{
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "name": name,
                    "uid": uid,
                    "controller": true,
                    "blockOwnerDeletion": true
                }]
            },
            "spec": spec,
            "status": {
                "phase": "Pending"
            }
        });

        self.client
            .create_pod(namespace, new_pod)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("pods/{pod_name}"),
                reason: e.to_string(),
            })?;
        Ok(())
    }

    async fn terminate_active_pods(&self, namespace: &str, active_pods: &[Value]) {
        for pod in active_pods {
            if let Some(pname) = pod.pointer("/metadata/name").and_then(Value::as_str) {
                let _ = self.client.delete_pod(namespace, pname).await;
            }
        }
    }

    /// Reconciles a single Job by creating or monitoring child Pods.
    #[allow(clippy::too_many_lines)]
    pub async fn reconcile_job(
        &self,
        namespace: &str,
        job: &Value,
    ) -> Result<Value, ControllerError> {
        let name = job
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ControllerError::InvalidConfiguration {
                field: "metadata.name".to_string(),
                reason: "Job missing metadata.name".to_string(),
            })?;

        let uid = job
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let deleting = job
            .pointer("/metadata/deletionTimestamp")
            .and_then(Value::as_str)
            .is_some();

        let owned_pods = super::adopt_and_release_pods(
            &self.client,
            namespace,
            "batch/v1",
            "Job",
            name,
            uid,
            deleting,
            job.pointer("/spec/selector"),
        )
        .await?;

        let suspended = job
            .pointer("/spec/suspend")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if suspended {
            let active_pods: Vec<Value> = owned_pods
                .into_iter()
                .filter(|p| {
                    !matches!(
                        p.pointer("/status/phase").and_then(Value::as_str),
                        Some("Succeeded" | "Failed")
                    )
                })
                .collect();
            if !active_pods.is_empty() {
                self.terminate_active_pods(namespace, &active_pods).await;
            }
            let now = diorama_apiserver::time::now_rfc3339();
            let conditions = json!([
                {
                    "type": "Suspended",
                    "status": "True",
                    "lastProbeTime": now,
                    "lastTransitionTime": now,
                    "reason": "JobSuspended",
                    "message": "Job suspended"
                }
            ]);
            return self
                .update_job_status(
                    namespace,
                    name,
                    job,
                    0,
                    0,
                    0,
                    0,
                    None,
                    None,
                    Some(conditions),
                    false,
                )
                .await;
        }

        if is_job_finished(job) {
            return Ok(job.clone());
        }

        let parallelism = job
            .get("spec")
            .and_then(|s| s.get("parallelism"))
            .and_then(Value::as_i64)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(1)
            .max(1);

        let completions = job
            .get("spec")
            .and_then(|s| s.get("completions"))
            .and_then(Value::as_i64)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(parallelism)
            .max(1);

        let indexed =
            job.pointer("/spec/completionMode").and_then(Value::as_str) == Some("Indexed");

        let backoff_limit = job
            .pointer("/spec/backoffLimit")
            .and_then(Value::as_i64)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(6);

        let backoff_limit_per_index = job
            .pointer("/spec/backoffLimitPerIndex")
            .and_then(Value::as_i64)
            .and_then(|v| usize::try_from(v).ok());

        let max_failed_indexes = job
            .pointer("/spec/maxFailedIndexes")
            .and_then(Value::as_i64)
            .and_then(|v| usize::try_from(v).ok());

        let template = job
            .get("spec")
            .and_then(|s| s.get("template"))
            .cloned()
            .unwrap_or_else(|| json!({ "spec": { "containers": [] } }));

        let mut template_labels = template
            .get("metadata")
            .and_then(|m| m.get("labels"))
            .cloned()
            .unwrap_or_else(|| json!({}));

        if let Some(labels_obj) = template_labels.as_object_mut() {
            labels_obj.insert("job-name".to_string(), json!(name));
            labels_obj.insert("batch.kubernetes.io/job-name".to_string(), json!(name));
            if !uid.is_empty() {
                labels_obj.insert("controller-uid".to_string(), json!(uid));
                labels_obj.insert("batch.kubernetes.io/controller-uid".to_string(), json!(uid));
            }
        }

        let template_annotations = template
            .get("metadata")
            .and_then(|m| m.get("annotations"))
            .cloned()
            .unwrap_or_else(|| json!({}));

        let template_spec = template
            .get("spec")
            .cloned()
            .unwrap_or_else(|| json!({ "containers": [] }));

        let mut succeeded_pods = Vec::new();
        let mut failed_pods = Vec::new();
        let mut active_pods = Vec::new();
        let mut succeeded_indexes = BTreeSet::new();
        let mut failed_indexes = BTreeSet::new();
        let mut fail_job_reason: Option<(&'static str, String)> = None;

        for pod in &owned_pods {
            let phase = pod
                .pointer("/status/phase")
                .and_then(Value::as_str)
                .unwrap_or("Pending");
            let pod_idx = extract_pod_completion_index(pod, name);
            match phase {
                "Succeeded" => {
                    succeeded_pods.push(pod.clone());
                    if let Some(idx) = pod_idx {
                        succeeded_indexes.insert(idx);
                    }
                },
                "Failed" => {
                    if let Some(reason) =
                        handle_failed_pod(job, pod, pod_idx, &mut failed_pods, &mut failed_indexes)
                    {
                        fail_job_reason = Some(reason);
                    }
                },
                _ => {
                    active_pods.push(pod.clone());
                },
            }
        }

        if indexed {
            if let Some(per_idx_limit) = backoff_limit_per_index {
                compute_per_index_failures(
                    completions,
                    per_idx_limit,
                    &succeeded_indexes,
                    &mut failed_indexes,
                    &failed_pods,
                    name,
                );
            }
            if let Some(max_failed) = max_failed_indexes
                && failed_indexes.len() > max_failed
            {
                fail_job_reason = Some((
                    "MaxFailedIndexesExceeded",
                    "Job has exceeded the specified maxFailedIndexes".to_string(),
                ));
            }
        }

        if fail_job_reason.is_none()
            && backoff_limit_per_index.is_none()
            && failed_pods.len() > backoff_limit
        {
            fail_job_reason = Some((
                "BackoffLimitExceeded",
                "Job has reached the specified backoff limit".to_string(),
            ));
        }

        if fail_job_reason.is_none()
            && indexed
            && succeeded_indexes.len() + failed_indexes.len() >= completions
            && !failed_indexes.is_empty()
        {
            fail_job_reason = Some(("FailedIndexes", "Job has failed indexes".to_string()));
        }

        let success_policy_met = evaluate_success_policy(job, &succeeded_indexes);
        let completions_reached = if indexed {
            succeeded_indexes.len() >= completions
        } else {
            succeeded_pods.len() >= completions
        };

        let now = diorama_apiserver::time::now_rfc3339();

        if let Some((reason, message)) = fail_job_reason {
            self.terminate_active_pods(namespace, &active_pods).await;
            active_pods.clear();
            let conditions = json!([
                {
                    "type": "FailureTarget",
                    "status": "True",
                    "lastProbeTime": now,
                    "lastTransitionTime": now,
                    "reason": reason,
                    "message": message
                },
                {
                    "type": "Failed",
                    "status": "True",
                    "lastProbeTime": now,
                    "lastTransitionTime": now,
                    "reason": reason,
                    "message": message
                }
            ]);
            return self
                .update_job_status(
                    namespace,
                    name,
                    job,
                    0,
                    0,
                    succeeded_pods.len(),
                    failed_pods.len(),
                    indexed.then(|| format_index_set(&succeeded_indexes)),
                    (!failed_indexes.is_empty()).then(|| format_index_set(&failed_indexes)),
                    Some(conditions),
                    false,
                )
                .await;
        }

        if success_policy_met || completions_reached {
            self.terminate_active_pods(namespace, &active_pods).await;
            let reason = if success_policy_met {
                "SuccessPolicy"
            } else {
                "CompletionsReached"
            };
            let conditions = json!([
                {
                    "type": "SuccessCriteriaMet",
                    "status": "True",
                    "lastProbeTime": now,
                    "lastTransitionTime": now,
                    "reason": reason,
                    "message": "Job satisfied completion criteria"
                },
                {
                    "type": "Complete",
                    "status": "True",
                    "lastProbeTime": now,
                    "lastTransitionTime": now,
                    "reason": reason,
                    "message": "Job completed"
                }
            ]);
            return self
                .update_job_status(
                    namespace,
                    name,
                    job,
                    0,
                    0,
                    succeeded_pods.len(),
                    failed_pods.len(),
                    indexed.then(|| format_index_set(&succeeded_indexes)),
                    (!failed_indexes.is_empty()).then(|| format_index_set(&failed_indexes)),
                    Some(conditions),
                    true,
                )
                .await;
        }

        // Scale up pods if needed
        if !deleting {
            let tpl = JobPodTemplate {
                labels: &template_labels,
                annotations: &template_annotations,
                spec: &template_spec,
            };
            if indexed {
                self.scale_up_indexed_pods(
                    namespace,
                    name,
                    uid,
                    parallelism,
                    completions,
                    &active_pods,
                    &succeeded_indexes,
                    &failed_indexes,
                    &owned_pods,
                    &tpl,
                )
                .await?;
            } else {
                self.scale_up_non_indexed_pods(
                    namespace,
                    name,
                    uid,
                    parallelism,
                    completions,
                    succeeded_pods.len(),
                    active_pods.len(),
                    &tpl,
                )
                .await?;
            }
        }

        let has_nodes = self
            .client
            .list_nodes()
            .await
            .ok()
            .and_then(|n| n.get("items").and_then(Value::as_array).cloned())
            .is_some_and(|items| !items.is_empty());

        let updated_pods = super::adopt_and_release_pods(
            &self.client,
            namespace,
            "batch/v1",
            "Job",
            name,
            uid,
            deleting,
            job.pointer("/spec/selector"),
        )
        .await?;

        let active_count = updated_pods
            .iter()
            .filter(|p| {
                !matches!(
                    p.pointer("/status/phase").and_then(Value::as_str),
                    Some("Succeeded" | "Failed")
                )
            })
            .count();
        let ready_count = if has_nodes {
            updated_pods
                .iter()
                .filter(|p| super::is_pod_ready(p))
                .count()
        } else {
            active_count
        };

        self.update_job_status(
            namespace,
            name,
            job,
            active_count,
            ready_count,
            succeeded_pods.len(),
            failed_pods.len(),
            indexed.then(|| format_index_set(&succeeded_indexes)),
            (!failed_indexes.is_empty()).then(|| format_index_set(&failed_indexes)),
            None,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_job_status(
        &self,
        namespace: &str,
        name: &str,
        job: &Value,
        active: usize,
        ready: usize,
        succeeded: usize,
        failed: usize,
        completed_indexes: Option<String>,
        failed_indexes: Option<String>,
        conditions: Option<Value>,
        completed: bool,
    ) -> Result<Value, ControllerError> {
        let is_suspended = job
            .pointer("/spec/suspend")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let now = diorama_apiserver::time::now_rfc3339();
        let existing_start_time = job.pointer("/status/startTime").and_then(Value::as_str);

        let start_time = if existing_start_time.is_none() && is_suspended {
            None
        } else {
            Some(existing_start_time.unwrap_or(&now).to_string())
        };

        let mut updated_job = job.clone();
        let status_obj = updated_job.as_object_mut().and_then(|obj| {
            obj.entry("status".to_string())
                .or_insert_with(|| json!({}))
                .as_object_mut()
        });

        if let Some(status) = status_obj {
            if let Some(st) = start_time {
                status.insert("startTime".to_string(), json!(st));
            }
            status.insert("active".to_string(), json!(active));
            status.insert("ready".to_string(), json!(ready));
            status.insert("succeeded".to_string(), json!(succeeded));
            status.insert("failed".to_string(), json!(failed));
            status.insert("uncountedTerminatedPods".to_string(), json!({}));
            if let Some(ci) = completed_indexes {
                status.insert("completedIndexes".to_string(), json!(ci));
            }
            if let Some(fi) = failed_indexes {
                status.insert("failedIndexes".to_string(), json!(fi));
            }
            if let Some(conds) = conditions {
                status.insert("conditions".to_string(), conds);
            } else if let Some(existing_conds) =
                status.get_mut("conditions").and_then(Value::as_array_mut)
            {
                resume_suspended_conditions(existing_conds, &now);
            }
            if completed {
                status
                    .entry("completionTime".to_string())
                    .or_insert_with(|| json!(now));
            }
        }

        if updated_job.get("status") == job.get("status") {
            return Ok(updated_job);
        }

        self.client
            .update_job(namespace, name, updated_job)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("jobs/{name}"),
                reason: e.to_string(),
            })
    }

    #[allow(clippy::too_many_arguments)]
    async fn scale_up_indexed_pods(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        parallelism: usize,
        completions: usize,
        active_pods: &[Value],
        succeeded_indexes: &BTreeSet<usize>,
        failed_indexes: &BTreeSet<usize>,
        owned_pods: &[Value],
        tpl: &JobPodTemplate<'_>,
    ) -> Result<(), ControllerError> {
        let active_indexes: BTreeSet<usize> = active_pods
            .iter()
            .filter_map(|p| extract_pod_completion_index(p, name))
            .collect();
        let mut currently_active = active_pods.len();
        for idx in 0..completions {
            if currently_active >= parallelism {
                break;
            }
            if succeeded_indexes.contains(&idx)
                || failed_indexes.contains(&idx)
                || active_indexes.contains(&idx)
            {
                continue;
            }
            let attempt = owned_pods
                .iter()
                .filter(|p| extract_pod_completion_index(p, name) == Some(idx))
                .count();
            let pod_name = if attempt == 0 {
                format!("{name}-{idx}")
            } else {
                format!("{name}-{idx}-r{attempt}")
            };
            if self.client.get_pod(namespace, &pod_name).await.is_ok() {
                continue;
            }
            self.create_job_pod(
                namespace,
                name,
                uid,
                &pod_name,
                Some(idx),
                tpl.labels,
                tpl.annotations,
                tpl.spec,
            )
            .await?;
            currently_active += 1;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn scale_up_non_indexed_pods(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        parallelism: usize,
        completions: usize,
        succeeded_len: usize,
        active_len: usize,
        tpl: &JobPodTemplate<'_>,
    ) -> Result<(), ControllerError> {
        let remaining_completions = completions.saturating_sub(succeeded_len);
        let desired_active = parallelism.min(remaining_completions);
        let needed = desired_active.saturating_sub(active_len);
        let mut created = 0;
        let mut idx = 0;
        while created < needed {
            let pod_name = format!("{name}-{idx}");
            idx += 1;
            if self.client.get_pod(namespace, &pod_name).await.is_ok() {
                continue;
            }
            self.create_job_pod(
                namespace,
                name,
                uid,
                &pod_name,
                None,
                tpl.labels,
                tpl.annotations,
                tpl.spec,
            )
            .await?;
            created += 1;
        }
        Ok(())
    }
}

struct JobPodTemplate<'a> {
    labels: &'a Value,
    annotations: &'a Value,
    spec: &'a Value,
}

fn handle_failed_pod(
    job: &Value,
    pod: &Value,
    pod_idx: Option<usize>,
    failed_pods: &mut Vec<Value>,
    failed_indexes: &mut BTreeSet<usize>,
) -> Option<(&'static str, String)> {
    let action = evaluate_pod_failure_policy(job, pod);
    match action {
        PodFailureAction::Ignore => None,
        PodFailureAction::FailJob => {
            failed_pods.push(pod.clone());
            Some((
                "PodFailurePolicy",
                "Pod failure policy matched FailJob action".to_string(),
            ))
        },
        PodFailureAction::FailIndex => {
            failed_pods.push(pod.clone());
            if let Some(idx) = pod_idx {
                failed_indexes.insert(idx);
            }
            None
        },
        PodFailureAction::Count => {
            failed_pods.push(pod.clone());
            None
        },
    }
}

fn compute_per_index_failures(
    completions: usize,
    per_idx_limit: usize,
    succeeded_indexes: &BTreeSet<usize>,
    failed_indexes: &mut BTreeSet<usize>,
    failed_pods: &[Value],
    name: &str,
) {
    for idx in 0..completions {
        if succeeded_indexes.contains(&idx) || failed_indexes.contains(&idx) {
            continue;
        }
        let idx_failures = failed_pods
            .iter()
            .filter(|p| extract_pod_completion_index(p, name) == Some(idx))
            .count();
        if idx_failures > per_idx_limit {
            failed_indexes.insert(idx);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PodFailureAction {
    Count,
    FailJob,
    FailIndex,
    Ignore,
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

fn inject_completion_index_env(spec: &mut Value, idx_str: &str) {
    for field in ["containers", "initContainers"] {
        let Some(containers) = spec.get_mut(field).and_then(Value::as_array_mut) else {
            continue;
        };
        for container in containers {
            let Some(c_obj) = container.as_object_mut() else {
                continue;
            };
            let env = c_obj.entry("env".to_string()).or_insert_with(|| json!([]));
            if let Some(env_arr) = env.as_array_mut() {
                let already_present = env_arr
                    .iter()
                    .any(|e| e.get("name").and_then(Value::as_str) == Some("JOB_COMPLETION_INDEX"));
                if !already_present {
                    env_arr.push(json!({
                        "name": "JOB_COMPLETION_INDEX",
                        "value": idx_str
                    }));
                }
            }
        }
    }
}

fn extract_pod_completion_index(pod: &Value, job_name: &str) -> Option<usize> {
    if let Some(idx_str) = pod
        .pointer("/metadata/labels/batch.kubernetes.io~1job-completion-index")
        .or_else(|| pod.pointer("/metadata/annotations/batch.kubernetes.io~1job-completion-index"))
        .and_then(Value::as_str)
        && let Ok(idx) = idx_str.parse::<usize>()
    {
        return Some(idx);
    }
    let pod_name = pod.pointer("/metadata/name").and_then(Value::as_str)?;
    let rest = pod_name.strip_prefix(&format!("{job_name}-"))?;
    let idx_part = rest.split('-').next()?;
    idx_part.parse::<usize>().ok()
}

fn evaluate_pod_failure_policy(job: &Value, pod: &Value) -> PodFailureAction {
    let Some(rules) = job
        .pointer("/spec/podFailurePolicy/rules")
        .and_then(Value::as_array)
    else {
        return PodFailureAction::Count;
    };

    for rule in rules {
        let action = match rule.get("action").and_then(Value::as_str) {
            Some("FailJob") => PodFailureAction::FailJob,
            Some("FailIndex") => PodFailureAction::FailIndex,
            Some("Ignore") => PodFailureAction::Ignore,
            _ => PodFailureAction::Count,
        };

        if let Some(on_exit) = rule.get("onExitCodes") {
            let operator = on_exit
                .get("operator")
                .and_then(Value::as_str)
                .unwrap_or("In");
            let target_container = on_exit.get("containerName").and_then(Value::as_str);
            let values: Vec<i64> = on_exit
                .get("values")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().filter_map(Value::as_i64).collect())
                .unwrap_or_default();

            let mut statuses = Vec::new();
            for status_field in ["/status/containerStatuses", "/status/initContainerStatuses"] {
                if let Some(arr) = pod.pointer(status_field).and_then(Value::as_array) {
                    statuses.extend(arr.iter());
                }
            }

            let matched = statuses.into_iter().any(|cs| {
                if let Some(tc) = target_container
                    && cs.get("name").and_then(Value::as_str) != Some(tc)
                {
                    return false;
                }
                let Some(exit_code) = cs
                    .pointer("/state/terminated/exitCode")
                    .and_then(Value::as_i64)
                else {
                    return false;
                };
                if exit_code == 0 {
                    return false;
                }
                match operator {
                    "In" => values.contains(&exit_code),
                    "NotIn" => !values.contains(&exit_code),
                    _ => false,
                }
            });

            if matched {
                return action;
            }
        }

        if let Some(on_conds) = rule.get("onPodConditions").and_then(Value::as_array) {
            let pod_conds = pod
                .pointer("/status/conditions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let matched = on_conds.iter().any(|pattern| {
                let p_type = pattern.get("type").and_then(Value::as_str);
                let p_status = pattern
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("True");
                pod_conds.iter().any(|pc| {
                    pc.get("type").and_then(Value::as_str) == p_type
                        && pc.get("status").and_then(Value::as_str) == Some(p_status)
                })
            });
            if matched {
                return action;
            }
        }
    }

    PodFailureAction::Count
}

fn evaluate_success_policy(job: &Value, succeeded_indexes: &BTreeSet<usize>) -> bool {
    let Some(rules) = job
        .pointer("/spec/successPolicy/rules")
        .and_then(Value::as_array)
    else {
        return false;
    };

    for rule in rules {
        let indexes_ok =
            if let Some(indexes_str) = rule.get("succeededIndexes").and_then(Value::as_str) {
                let required = parse_index_set(indexes_str);
                !required.is_empty() && required.is_subset(succeeded_indexes)
            } else {
                true
            };

        let count_ok = if let Some(req_count) = rule
            .get("succeededCount")
            .and_then(Value::as_i64)
            .and_then(|v| usize::try_from(v).ok())
        {
            succeeded_indexes.len() >= req_count
        } else {
            true
        };

        let has_constraint =
            rule.get("succeededIndexes").is_some() || rule.get("succeededCount").is_some();
        if has_constraint && indexes_ok && count_ok {
            return true;
        }
    }

    false
}

fn parse_index_set(spec: &str) -> BTreeSet<usize> {
    let mut set = BTreeSet::new();
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((start_s, end_s)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (
                start_s.trim().parse::<usize>(),
                end_s.trim().parse::<usize>(),
            ) && start <= end
            {
                for idx in start..=end {
                    set.insert(idx);
                }
            }
        } else if let Ok(idx) = part.parse::<usize>() {
            set.insert(idx);
        }
    }
    set
}

fn format_index_set(indexes: &BTreeSet<usize>) -> String {
    let mut intervals: Vec<(usize, usize)> = Vec::new();
    for &idx in indexes {
        if let Some(last) = intervals.last_mut()
            && idx == last.1 + 1
        {
            last.1 = idx;
            continue;
        }
        intervals.push((idx, idx));
    }

    intervals
        .into_iter()
        .map(|(start, end)| {
            if start == end {
                start.to_string()
            } else if end == start + 1 {
                format!("{start},{end}")
            } else {
                format!("{start}-{end}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn resume_suspended_conditions(conds: &mut [Value], now: &str) {
    for c in conds {
        if c.get("type").and_then(Value::as_str) == Some("Suspended") {
            c["status"] = json!("False");
            c["reason"] = json!("JobResumed");
            c["message"] = json!("Job resumed");
            c["lastTransitionTime"] = json!(now);
        }
    }
}
