use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use diorama_apiserver::{ApiserverService, KubernetesApiClient};

use crate::config::ControllerManagerConfig;
use crate::error::ControllerError;
use crate::health::ControllerHealthReport;
use crate::workload::{ReconciliationSummary, WorkloadManager};

pub const CONTROLLER_MANAGER_USER: &str = "system:kube-controller-manager";
pub const CONTROLLER_LEADER_LEASE_NAMESPACE: &str = "kube-system";
pub const CONTROLLER_LEADER_LEASE_NAME: &str = "kube-controller-manager";

#[derive(Clone, Debug)]
pub struct ControllerManagerService {
    config: ControllerManagerConfig,
    apiserver: Arc<ApiserverService>,
    running: Arc<AtomicBool>,
    leader_identity: Option<String>,
    lease_duration_seconds: u64,
}

impl ControllerManagerService {
    pub fn new(config: ControllerManagerConfig, apiserver: Arc<ApiserverService>) -> Self {
        Self {
            config,
            apiserver,
            running: Arc::new(AtomicBool::new(false)),
            leader_identity: None,
            lease_duration_seconds: 15,
        }
    }

    #[must_use]
    pub fn with_leader_election(
        mut self,
        holder_identity: impl Into<String>,
        lease_duration_seconds: u64,
    ) -> Self {
        self.leader_identity = Some(holder_identity.into());
        self.lease_duration_seconds = lease_duration_seconds.max(1);
        self
    }

    #[must_use]
    pub fn config(&self) -> &ControllerManagerConfig {
        &self.config
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Obtains an authenticated Kubernetes API client using the controller-manager identity.
    #[must_use]
    pub fn client(&self) -> KubernetesApiClient {
        self.apiserver.controller_manager_client()
    }

    /// Obtains a workload manager configured with the controller-manager API client.
    #[must_use]
    pub fn workload_manager(&self) -> WorkloadManager {
        WorkloadManager::new(Arc::new(self.client()))
    }

    /// Checks that all required credentials exist, the configuration has no dropped
    /// controllers, and the API server is reachable with controller-manager identity.
    pub async fn check_prerequisites(&self) -> Result<(), ControllerError> {
        // 1. Verify credential file paths
        if !self.config.kubeconfig.exists() {
            return Err(ControllerError::MissingCredential {
                path: self.config.kubeconfig.clone(),
                component: "kubeconfig",
            });
        }

        if !self.config.root_ca_file.exists() {
            return Err(ControllerError::MissingCredential {
                path: self.config.root_ca_file.clone(),
                component: "root-ca",
            });
        }

        if !self.config.service_account_private_key_file.exists() {
            return Err(ControllerError::MissingCredential {
                path: self.config.service_account_private_key_file.clone(),
                component: "service-account-key",
            });
        }

        // Validate kubeconfig content and user identity
        let kubeconfig_content = std::fs::read_to_string(&self.config.kubeconfig).map_err(|e| {
            ControllerError::InvalidConfiguration {
                field: "kubeconfig".to_string(),
                reason: format!("failed to read kubeconfig: {e}"),
            }
        })?;
        if !kubeconfig_content.contains("kube-controller-manager") {
            return Err(ControllerError::AuthenticationFailed {
                reason: "kubeconfig missing kube-controller-manager identity".to_string(),
            });
        }

        // 2. Validate configuration against historical allowlists and upstream defaults
        self.config.validate_controllers()?;
        self.config.validate_batch_periods()?;

        // 3. Verify API server health & controller-manager authentication
        let client = self.client();
        client
            .list_namespaces()
            .await
            .map_err(|e| ControllerError::AuthenticationFailed {
                reason: format!("failed to list namespaces with controller-manager identity: {e}"),
            })?;

        Ok(())
    }

    /// Starts the controller manager service.
    pub async fn start(&self) -> Result<(), ControllerError> {
        self.check_prerequisites().await?;
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Checks the health and readiness of the controller manager service.
    pub async fn check_readiness(&self) -> Result<ControllerHealthReport, ControllerError> {
        if !self.is_running() {
            return Ok(ControllerHealthReport::new_unhealthy(
                "controller manager service is not running",
            ));
        }

        // Verify API server connectivity
        let client = self.client();
        if let Err(e) = client.list_namespaces().await {
            return Ok(ControllerHealthReport::new_unhealthy(format!(
                "API server communication failed: {e}"
            )));
        }

        let configured = if self.config.controllers.iter().any(|c| c == "*") {
            crate::config::REQUIRED_CONTROLLERS
                .iter()
                .map(|&s| s.to_string())
                .collect()
        } else {
            self.config.controllers.clone()
        };

        // Populated with active workload and garbage-collection reconciliation loops (E12.02, E12.03)
        let workload_controllers = [
            "cronjob",
            "daemonset",
            "deployment",
            "endpoints",
            "endpointslice",
            "garbagecollector",
            "job",
            "replicaset",
            "statefulset",
        ];
        let mut active = Vec::new();
        for wc in workload_controllers {
            if self
                .config
                .controllers
                .iter()
                .any(|c| c == "*" || c.trim_start_matches('+') == wc)
            {
                active.push(wc.to_string());
            }
        }
        active.sort();

        Ok(ControllerHealthReport::new_healthy(configured, active))
    }

    /// Stops the controller manager service.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Acquires or renews the `coordination.k8s.io/v1` `Lease` in `kube-system/kube-controller-manager`
    /// when multi-node leader election is enabled.
    pub async fn try_acquire_or_renew_leader_lease(&self) -> Result<bool, ControllerError> {
        let Some(holder_id) = &self.leader_identity else {
            return Ok(true);
        };

        let client = self.client();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let renew_time = now_secs.to_string();

        let lease_doc = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": CONTROLLER_LEADER_LEASE_NAME,
                "namespace": CONTROLLER_LEADER_LEASE_NAMESPACE,
            },
            "spec": {
                "holderIdentity": holder_id,
                "leaseDurationSeconds": self.lease_duration_seconds,
                "renewTime": renew_time,
            }
        });

        match client
            .get_lease(
                CONTROLLER_LEADER_LEASE_NAMESPACE,
                CONTROLLER_LEADER_LEASE_NAME,
            )
            .await
        {
            Ok(existing) => {
                let current_holder = existing
                    .pointer("/spec/holderIdentity")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let last_renew = existing
                    .pointer("/spec/renewTime")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|s| s.parse::<u64>().ok());
                let duration = existing
                    .pointer("/spec/leaseDurationSeconds")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(self.lease_duration_seconds);
                let expired = last_renew.is_none_or(|r| now_secs.saturating_sub(r) >= duration);

                if current_holder != holder_id && !current_holder.is_empty() && !expired {
                    return Ok(false);
                }

                let mut updated = lease_doc;
                if let Some(rv) = existing.pointer("/metadata/resourceVersion")
                    && let Some(meta) = updated
                        .get_mut("metadata")
                        .and_then(serde_json::Value::as_object_mut)
                {
                    meta.insert("resourceVersion".to_string(), rv.clone());
                }

                match client
                    .update_lease(
                        CONTROLLER_LEADER_LEASE_NAMESPACE,
                        CONTROLLER_LEADER_LEASE_NAME,
                        updated,
                    )
                    .await
                {
                    Ok(_) => Ok(true),
                    Err(diorama_apiserver::ApiserverError::Conflict { .. }) => Ok(false),
                    Err(e) => Err(ControllerError::ReconciliationFailed {
                        resource: CONTROLLER_LEADER_LEASE_NAME.to_string(),
                        reason: e.to_string(),
                    }),
                }
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                let _ = client
                    .create_namespace(CONTROLLER_LEADER_LEASE_NAMESPACE)
                    .await;
                match client
                    .create_lease(CONTROLLER_LEADER_LEASE_NAMESPACE, lease_doc)
                    .await
                {
                    Ok(_) => Ok(true),
                    Err(diorama_apiserver::ApiserverError::Conflict { .. }) => Ok(false),
                    Err(e) => Err(ControllerError::ReconciliationFailed {
                        resource: CONTROLLER_LEADER_LEASE_NAME.to_string(),
                        reason: e.to_string(),
                    }),
                }
            },
            Err(e) => Err(ControllerError::ReconciliationFailed {
                resource: CONTROLLER_LEADER_LEASE_NAME.to_string(),
                reason: e.to_string(),
            }),
        }
    }

    /// Reconciles workloads and endpoints across all namespaces in the cluster.
    pub async fn reconcile_all(&self) -> Result<Vec<ReconciliationSummary>, ControllerError> {
        if !self.try_acquire_or_renew_leader_lease().await? {
            return Ok(Vec::new());
        }
        let client = self.client();
        let namespaces = list_active_namespaces(&client).await;
        // The root-ca publisher keeps kube-root-ca.crt in every namespace.
        // A missing or edited ConfigMap is repaired on this pass.
        for namespace in &namespaces {
            if let Err(err) = client.ensure_kube_root_ca_configmap(namespace).await {
                tracing::warn!(namespace, error = %err, "root ca publisher failed");
            }
        }
        let workload_mgr = self.workload_manager();
        let mut summaries = Vec::new();
        for ns in &namespaces {
            let summary = workload_mgr.reconcile_namespace(ns).await?;
            summaries.push(summary);
        }
        let _ = self.schedule_unassigned_pods(&namespaces).await;
        Ok(summaries)
    }

    /// Binds unscheduled pods (`spec.nodeName` unset) across registered cluster nodes in round-robin order.
    pub async fn schedule_unassigned_pods(&self, namespaces: &[String]) -> usize {
        let Ok(raw_nodes) = self.apiserver.storage().list("/registry/nodes").await else {
            return 0;
        };
        let mut nodes: Vec<(String, serde_json::Value)> = raw_nodes
            .into_iter()
            .filter_map(|kv| serde_json::from_slice::<serde_json::Value>(&kv.value).ok())
            .filter_map(|node| {
                let name = node
                    .pointer("/metadata/name")
                    .and_then(serde_json::Value::as_str)?
                    .to_string();
                Some((name, node))
            })
            .collect();
        nodes.sort_by(|a, b| a.0.cmp(&b.0));
        if nodes.is_empty() {
            return 0;
        }

        let client = self.client();
        let mut scheduled = 0usize;
        let mut cursor = 0usize;
        for ns in namespaces {
            let Ok(pod_list) = client.list_pods(ns).await else {
                continue;
            };
            let Some(items) = pod_list.get("items").and_then(serde_json::Value::as_array) else {
                continue;
            };
            for pod in items {
                scheduled += try_schedule_pod(&client, ns, pod, &nodes, &mut cursor).await;
            }
        }
        scheduled
    }

    /// Performs a single reconciliation pass over all workloads in all active namespaces.
    pub async fn reconcile_once(&self) -> Result<usize, ControllerError> {
        let summaries = self.reconcile_all().await?;
        for summary in &summaries {
            if !summary.errors.is_empty() {
                tracing::warn!(
                    errors = ?summary.errors,
                    "controller reconciliation encountered errors"
                );
            }
        }
        Ok(summaries
            .iter()
            .map(ReconciliationSummary::total_workloads)
            .sum())
    }
}

async fn list_active_namespaces(
    client: &diorama_apiserver::client::KubernetesApiClient,
) -> Vec<String> {
    let Ok(val) = client.list_namespaces().await else {
        return vec!["default".to_string(), "kube-system".to_string()];
    };

    let items = val.get("items").and_then(serde_json::Value::as_array);
    let ns_list: Vec<String> = items
        .into_iter()
        .flatten()
        .filter_map(|item| {
            item.pointer("/metadata/name")
                .and_then(serde_json::Value::as_str)
        })
        .map(ToString::to_string)
        .collect();

    if ns_list.is_empty() {
        vec!["default".to_string(), "kube-system".to_string()]
    } else {
        ns_list
    }
}

async fn try_schedule_pod(
    client: &diorama_apiserver::client::KubernetesApiClient,
    namespace: &str,
    pod: &serde_json::Value,
    nodes: &[(String, serde_json::Value)],
    cursor: &mut usize,
) -> usize {
    if pod
        .pointer("/spec/nodeName")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|n| !n.is_empty())
    {
        return 0;
    }
    let Some(pod_name) = pod
        .pointer("/metadata/name")
        .and_then(serde_json::Value::as_str)
    else {
        return 0;
    };

    let selector = pod
        .pointer("/spec/nodeSelector")
        .and_then(serde_json::Value::as_object);
    let candidates: Vec<&str> = nodes
        .iter()
        .filter(|(_, node_val)| {
            selector.is_none_or(|sel| {
                sel.iter().all(|(k, v)| {
                    node_val.pointer("/metadata/labels").and_then(|l| l.get(k)) == Some(v)
                })
            })
        })
        .map(|(name, _)| name.as_str())
        .collect();
    if candidates.is_empty() {
        return 0;
    }

    let chosen = candidates[*cursor % candidates.len()];
    *cursor = cursor.wrapping_add(1);

    let mut updated = pod.clone();
    if let Some(spec) = updated
        .get_mut("spec")
        .and_then(serde_json::Value::as_object_mut)
    {
        spec.insert(
            "nodeName".to_string(),
            serde_json::Value::String(chosen.to_string()),
        );
    }
    usize::from(
        client
            .update_pod(namespace, pod_name, updated)
            .await
            .is_ok(),
    )
}
