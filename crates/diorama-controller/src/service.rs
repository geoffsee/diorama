use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use diorama_apiserver::{ApiserverService, KubernetesApiClient};

use crate::config::ControllerManagerConfig;
use crate::error::ControllerError;
use crate::health::ControllerHealthReport;
use crate::workload::{ReconciliationSummary, WorkloadManager};

pub const CONTROLLER_MANAGER_USER: &str = "system:kube-controller-manager";

#[derive(Clone, Debug)]
pub struct ControllerManagerService {
    config: ControllerManagerConfig,
    apiserver: Arc<ApiserverService>,
    running: Arc<AtomicBool>,
}

impl ControllerManagerService {
    pub fn new(config: ControllerManagerConfig, apiserver: Arc<ApiserverService>) -> Self {
        Self {
            config,
            apiserver,
            running: Arc::new(AtomicBool::new(false)),
        }
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

    /// Reconciles workloads and endpoints across all namespaces in the cluster.
    pub async fn reconcile_all(&self) -> Result<Vec<ReconciliationSummary>, ControllerError> {
        let client = self.client();
        let namespaces = list_active_namespaces(&client).await;
        let workload_mgr = self.workload_manager();
        let mut summaries = Vec::new();
        for ns in &namespaces {
            let summary = workload_mgr.reconcile_namespace(ns).await?;
            summaries.push(summary);
        }
        Ok(summaries)
    }

    /// Performs a single reconciliation pass over all workloads in all active namespaces.
    pub async fn reconcile_once(&self) -> Result<usize, ControllerError> {
        let summaries = self.reconcile_all().await?;
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
