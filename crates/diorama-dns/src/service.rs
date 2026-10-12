use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use diorama_apiserver::client::KubernetesApiClient;
use diorama_apiserver::service::ApiserverService;
use tokio::sync::RwLock;
use tracing::info;

use crate::config::{COREDNS_DEPLOYMENT_NAME, COREDNS_NAMESPACE, CoreDnsConfig};
use crate::error::{DnsError, Result};
use crate::health::CoreDnsHealthReport;
use crate::reconciler::{DnsReconciler, ReconciliationReport};

/// Managed `CoreDNS` service governing deployment reconciliation, readiness, and lifecycle.
#[derive(Clone)]
pub struct CoreDnsService {
    config: CoreDnsConfig,
    client: Arc<KubernetesApiClient>,
    running: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    last_report: Arc<RwLock<Option<ReconciliationReport>>>,
}

impl std::fmt::Debug for CoreDnsService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreDnsService")
            .field("config", &self.config)
            .field("running", &self.is_running())
            .field("ready", &self.is_ready())
            .finish_non_exhaustive()
    }
}

impl CoreDnsService {
    /// Creates a new `CoreDnsService` with an authenticated Kubernetes API client.
    #[must_use]
    pub fn new(config: CoreDnsConfig, client: Arc<KubernetesApiClient>) -> Self {
        Self {
            config,
            client,
            running: Arc::new(AtomicBool::new(false)),
            ready: Arc::new(AtomicBool::new(false)),
            last_report: Arc::new(RwLock::new(None)),
        }
    }

    /// Creates a new `CoreDnsService` using the admin client from an `ApiserverService`.
    #[must_use]
    pub fn from_apiserver(config: CoreDnsConfig, apiserver: &ApiserverService) -> Self {
        Self::new(config, Arc::new(apiserver.admin_client()))
    }

    #[must_use]
    pub fn config(&self) -> &CoreDnsConfig {
        &self.config
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

    /// Verifies that the Kubernetes API is reachable and prerequisites are satisfied.
    pub async fn check_prerequisites(&self) -> Result<()> {
        self.client
            .list_namespaces()
            .await
            .map_err(|e| DnsError::Api(format!("failed to connect to apiserver: {e}")))?;
        Ok(())
    }

    /// Reconciles all `CoreDNS` manifests into the cluster.
    pub async fn reconcile(&self) -> Result<ReconciliationReport> {
        let reconciler = DnsReconciler::new(&self.config);
        let report = reconciler.reconcile(&self.client).await?;
        *self.last_report.write().await = Some(report.clone());
        Ok(report)
    }

    /// Waits for the `CoreDNS` deployment to report at least one ready replica within timeout.
    pub async fn wait_for_readiness(&self, timeout: Duration) -> Result<()> {
        let reconciler = DnsReconciler::new(&self.config);
        reconciler
            .wait_for_readiness(&self.client, timeout, Duration::from_millis(100))
            .await?;
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Starts the `CoreDNS` service by reconciling all resources into the cluster.
    pub async fn start(&self) -> Result<ReconciliationReport> {
        info!("starting CoreDNS service reconciliation");
        self.running.store(true, Ordering::SeqCst);
        self.reconcile().await
    }

    /// Checks the health and readiness of the `CoreDNS` deployment.
    pub async fn check_readiness(&self) -> Result<CoreDnsHealthReport> {
        match self
            .client
            .get_deployment(COREDNS_NAMESPACE, COREDNS_DEPLOYMENT_NAME)
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

                Ok(CoreDnsHealthReport {
                    is_healthy,
                    deployment_found: true,
                    ready_replicas: ready_i32,
                    desired_replicas: desired_i32,
                    message: if is_healthy {
                        format!("CoreDNS is healthy ({ready_i32}/{desired_i32} ready)")
                    } else {
                        format!("CoreDNS has no ready replicas ({ready_i32}/{desired_i32})")
                    },
                })
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                self.ready.store(false, Ordering::SeqCst);
                Ok(CoreDnsHealthReport {
                    is_healthy: false,
                    deployment_found: false,
                    ready_replicas: 0,
                    desired_replicas: 1,
                    message: "CoreDNS deployment not found in cluster".to_string(),
                })
            },
            Err(err) => Err(DnsError::Apiserver(err)),
        }
    }

    /// Stops the `CoreDNS` service.
    pub fn stop(&self) {
        info!("stopping CoreDNS service");
        self.running.store(false, Ordering::SeqCst);
        self.ready.store(false, Ordering::SeqCst);
    }
}
