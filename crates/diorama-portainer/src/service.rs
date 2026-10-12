use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use diorama_apiserver::client::KubernetesApiClient;
use diorama_apiserver::service::ApiserverService;
use tokio::sync::RwLock;
use tracing::info;

use crate::config::PortainerAgentConfig;
use crate::error::{PortainerError, Result};
use crate::reconciler::{PortainerReconciler, PortainerReconciliationReport};

/// Managed Portainer Edge Agent service governing deployment reconciliation, readiness, and lifecycle.
#[derive(Clone)]
pub struct PortainerService {
    config: PortainerAgentConfig,
    client: Arc<KubernetesApiClient>,
    running: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    last_report: Arc<RwLock<Option<PortainerReconciliationReport>>>,
}

impl std::fmt::Debug for PortainerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortainerService")
            .field("config", &self.config)
            .field("running", &self.is_running())
            .field("ready", &self.is_ready())
            .finish_non_exhaustive()
    }
}

impl PortainerService {
    /// Creates a new `PortainerService` with an authenticated Kubernetes API client.
    #[must_use]
    pub fn new(config: PortainerAgentConfig, client: Arc<KubernetesApiClient>) -> Self {
        Self {
            config,
            client,
            running: Arc::new(AtomicBool::new(false)),
            ready: Arc::new(AtomicBool::new(false)),
            last_report: Arc::new(RwLock::new(None)),
        }
    }

    /// Creates a new `PortainerService` using the admin client from an `ApiserverService`.
    #[must_use]
    pub fn from_apiserver(config: PortainerAgentConfig, apiserver: &ApiserverService) -> Self {
        Self::new(config, Arc::new(apiserver.admin_client()))
    }

    /// Returns a reference to the active configuration.
    #[must_use]
    pub fn config(&self) -> &PortainerAgentConfig {
        &self.config
    }

    /// Returns a reference to the Kubernetes API client.
    #[must_use]
    pub fn client(&self) -> &Arc<KubernetesApiClient> {
        &self.client
    }

    /// Returns whether the service has been started.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Returns whether the Portainer agent deployment is verified ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// Obtains the most recent reconciliation report, if any reconciliation has occurred.
    pub async fn last_reconciliation(&self) -> Option<PortainerReconciliationReport> {
        self.last_report.read().await.clone()
    }

    /// Verifies that the Kubernetes API is reachable and prerequisites are satisfied.
    pub async fn check_prerequisites(&self) -> Result<()> {
        self.client
            .list_namespaces()
            .await
            .map_err(|e| PortainerError::Api(format!("failed to connect to apiserver: {e}")))?;
        Ok(())
    }

    /// Reconciles all Portainer Edge Agent manifests into the cluster using create-only semantics.
    pub async fn reconcile(&self) -> Result<PortainerReconciliationReport> {
        if !self.config.is_enabled() {
            if self.config.has_partial_credentials() {
                return Err(PortainerError::IncompleteCredentials {
                    has_id: !self.config.edge_id.is_empty(),
                    has_key: !self.config.edge_key.is_empty(),
                });
            }
            if !self.config.is_architecture_supported() {
                return Err(PortainerError::UnsupportedArchitecture(
                    self.config.architecture,
                ));
            }
            return Ok(PortainerReconciliationReport::default());
        }

        let reconciler = PortainerReconciler::new(&self.config);
        let report = reconciler.reconcile(&self.client).await?;
        *self.last_report.write().await = Some(report.clone());
        Ok(report)
    }

    /// Waits for the Portainer deployment to report at least one ready replica within timeout.
    pub async fn wait_for_readiness(&self, timeout: Duration) -> Result<()> {
        if !self.config.is_enabled() {
            self.ready.store(true, Ordering::SeqCst);
            return Ok(());
        }

        let reconciler = PortainerReconciler::new(&self.config);
        reconciler
            .wait_for_readiness(&self.client, timeout, Duration::from_millis(100))
            .await?;
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Starts the Portainer Edge Agent service by reconciling all resources into the cluster.
    pub async fn start(&self) -> Result<PortainerReconciliationReport> {
        info!("starting Portainer Edge Agent service reconciliation");
        self.running.store(true, Ordering::SeqCst);
        self.reconcile().await
    }

    /// Stops the Portainer service.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.ready.store(false, Ordering::SeqCst);
    }
}
