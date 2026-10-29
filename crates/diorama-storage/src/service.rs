use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use diorama_apiserver::client::KubernetesApiClient;
use diorama_apiserver::service::ApiserverService;
use tokio::sync::RwLock;
use tracing::info;

use crate::config::{LOCAL_PATH_DEPLOYMENT_NAME, LOCAL_PATH_NAMESPACE, LocalPathConfig};
use crate::error::{Result, StorageError};
use crate::health::LocalPathHealthReport;
use crate::reconciler::{LocalPathReconciler, ReconciliationReport};
use crate::volume::LocalPathVolumeManager;

/// Managed `local-path` storage service governing deployment reconciliation, readiness, and lifecycle.
#[derive(Clone)]
pub struct LocalPathService {
    config: LocalPathConfig,
    client: Arc<KubernetesApiClient>,
    running: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    last_report: Arc<RwLock<Option<ReconciliationReport>>>,
    injected_failure: Arc<AtomicBool>,
}

impl std::fmt::Debug for LocalPathService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalPathService")
            .field("config", &self.config)
            .field("running", &self.is_running())
            .field("ready", &self.is_ready())
            .finish_non_exhaustive()
    }
}

impl LocalPathService {
    /// Creates a new `LocalPathService` with an authenticated Kubernetes API client.
    #[must_use]
    pub fn new(config: LocalPathConfig, client: Arc<KubernetesApiClient>) -> Self {
        Self {
            config,
            client,
            running: Arc::new(AtomicBool::new(false)),
            ready: Arc::new(AtomicBool::new(false)),
            last_report: Arc::new(RwLock::new(None)),
            injected_failure: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Creates a new `LocalPathService` using the admin client from an `ApiserverService`.
    #[must_use]
    pub fn from_apiserver(config: LocalPathConfig, apiserver: &ApiserverService) -> Self {
        Self::new(config, Arc::new(apiserver.admin_client()))
    }

    #[must_use]
    pub fn config(&self) -> &LocalPathConfig {
        &self.config
    }

    #[must_use]
    pub fn client(&self) -> &Arc<KubernetesApiClient> {
        &self.client
    }

    #[must_use]
    pub fn volume_manager(&self) -> LocalPathVolumeManager {
        LocalPathVolumeManager::new(self.config.clone(), (*self.client).clone())
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// Obtains the most recent reconciliation report, if any reconciliation has occurred.
    pub async fn last_reconciliation(&self) -> Option<ReconciliationReport> {
        self.last_report.read().await.clone()
    }

    /// Injects or clears a deployment failure for fault-tolerance verification.
    pub fn set_injected_failure(&self, fail: bool) {
        self.injected_failure.store(fail, Ordering::SeqCst);
    }

    /// Verifies that the Kubernetes API is reachable and prerequisites are satisfied.
    pub async fn check_prerequisites(&self) -> Result<()> {
        if self.injected_failure.load(Ordering::SeqCst) {
            return Err(StorageError::InjectedFailure(
                "injected local-path prerequisite check failure".to_string(),
            ));
        }

        self.client
            .list_namespaces()
            .await
            .map_err(|e| StorageError::Api(format!("failed to connect to apiserver: {e}")))?;
        Ok(())
    }

    /// Reconciles all local-path storage manifests into the cluster.
    pub async fn reconcile(&self) -> Result<ReconciliationReport> {
        if self.injected_failure.load(Ordering::SeqCst) {
            return Err(StorageError::InjectedFailure(
                "injected local-path deployment reconciliation failure".to_string(),
            ));
        }

        let reconciler = LocalPathReconciler::new(&self.config);
        let report = reconciler.reconcile(&self.client).await?;
        *self.last_report.write().await = Some(report.clone());
        Ok(report)
    }

    /// Waits for the `local-path-provisioner` deployment to report ready replicas.
    pub async fn wait_for_readiness(&self, timeout: Duration) -> Result<()> {
        if !self.config.enabled {
            self.ready.store(true, Ordering::SeqCst);
            return Ok(());
        }

        if self.injected_failure.load(Ordering::SeqCst) {
            return Err(StorageError::InjectedFailure(
                "injected local-path readiness failure".to_string(),
            ));
        }

        let reconciler = LocalPathReconciler::new(&self.config);
        reconciler
            .wait_for_readiness(&self.client, timeout, Duration::from_millis(50))
            .await?;
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Starts the local-path storage service by reconciling all resources into the cluster.
    pub async fn start(&self) -> Result<ReconciliationReport> {
        info!("starting local-path storage service reconciliation");
        self.running.store(true, Ordering::SeqCst);
        self.reconcile().await
    }

    /// Checks the health and readiness of the local-path provisioner deployment.
    pub async fn check_readiness(&self) -> Result<LocalPathHealthReport> {
        if !self.config.enabled {
            self.ready.store(true, Ordering::SeqCst);
            return Ok(LocalPathHealthReport {
                is_healthy: true,
                deployment_found: false,
                ready_replicas: 0,
                desired_replicas: 0,
                message: "local-path storage provisioner is disabled".to_string(),
            });
        }

        match self
            .client
            .get_deployment(LOCAL_PATH_NAMESPACE, LOCAL_PATH_DEPLOYMENT_NAME)
            .await
        {
            Ok(doc) => {
                let ready_replicas = doc
                    .get("status")
                    .and_then(|s| s.get("readyReplicas"))
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0);

                let desired_replicas = doc
                    .get("spec")
                    .and_then(|s| s.get("replicas"))
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(1);

                let ready_i32 = i32::try_from(ready_replicas).unwrap_or(0);
                let desired_i32 = i32::try_from(desired_replicas).unwrap_or(1);
                let is_healthy = ready_i32 > 0;
                self.ready.store(is_healthy, Ordering::SeqCst);

                Ok(LocalPathHealthReport {
                    is_healthy,
                    deployment_found: true,
                    ready_replicas: ready_i32,
                    desired_replicas: desired_i32,
                    message: if is_healthy {
                        format!(
                            "local-path provisioner is healthy ({ready_i32}/{desired_i32} ready)"
                        )
                    } else {
                        format!(
                            "local-path provisioner has no ready replicas ({ready_i32}/{desired_i32})"
                        )
                    },
                })
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                self.ready.store(false, Ordering::SeqCst);
                Ok(LocalPathHealthReport {
                    is_healthy: false,
                    deployment_found: false,
                    ready_replicas: 0,
                    desired_replicas: 1,
                    message: "local-path provisioner deployment not found in cluster".to_string(),
                })
            },
            Err(err) => Err(StorageError::Apiserver(err)),
        }
    }

    /// Stops the local-path storage service.
    pub fn stop(&self) {
        info!("stopping local-path storage service");
        self.running.store(false, Ordering::SeqCst);
        self.ready.store(false, Ordering::SeqCst);
    }
}
