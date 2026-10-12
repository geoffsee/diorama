use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use diorama_apiserver::ApiserverService;
use tokio::sync::watch;

use super::config::{DEFAULT_WEBHOOK_NAME, WebhookConfig};
use super::error::WebhookError;
use super::handler::NodeSetterHandler;
use super::server::WebhookServer;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookHealthReport {
    pub is_healthy: bool,
    pub component: String,
    pub endpoint: String,
    pub load_balancer_enabled: bool,
    pub message: String,
}

impl WebhookHealthReport {
    #[must_use]
    pub fn new_healthy(endpoint: &str, load_balancer_enabled: bool) -> Self {
        Self {
            is_healthy: true,
            component: "webhook".to_string(),
            endpoint: endpoint.to_string(),
            load_balancer_enabled,
            message: "webhook server is running and ready".to_string(),
        }
    }

    #[must_use]
    pub fn new_unhealthy(endpoint: &str, message: &str) -> Self {
        Self {
            is_healthy: false,
            component: "webhook".to_string(),
            endpoint: endpoint.to_string(),
            load_balancer_enabled: false,
            message: message.to_string(),
        }
    }
}

#[derive(Debug)]
pub struct WebhookService {
    config: WebhookConfig,
    apiserver: Arc<ApiserverService>,
    handler: Arc<NodeSetterHandler>,
    running: Arc<AtomicBool>,
    lifecycle_lock: Arc<tokio::sync::Mutex<()>>,
    shutdown_tx: Arc<tokio::sync::Mutex<Option<watch::Sender<bool>>>>,
    server_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl WebhookService {
    #[must_use]
    pub fn new(config: WebhookConfig, apiserver: Arc<ApiserverService>) -> Self {
        let admin = apiserver.admin_client();
        let handler = Arc::new(
            NodeSetterHandler::new(
                &config.node_name,
                &config.load_balancer_ip,
                config.load_balancer,
            )
            .with_client(Arc::new(admin)),
        );

        Self {
            config,
            apiserver,
            handler,
            running: Arc::new(AtomicBool::new(false)),
            lifecycle_lock: Arc::new(tokio::sync::Mutex::new(())),
            shutdown_tx: Arc::new(tokio::sync::Mutex::new(None)),
            server_task: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    #[must_use]
    pub fn config(&self) -> &WebhookConfig {
        &self.config
    }

    #[must_use]
    pub fn handler(&self) -> &Arc<NodeSetterHandler> {
        &self.handler
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Verifies TLS certificates, keys, and API server availability.
    pub async fn check_prerequisites(&self) -> Result<(), WebhookError> {
        if !self.config.cert_file.exists() {
            return Err(WebhookError::MissingCredential {
                path: self.config.cert_file.clone(),
                component: "webhook-cert",
            });
        }

        if !self.config.key_file.exists() {
            return Err(WebhookError::MissingCredential {
                path: self.config.key_file.clone(),
                component: "webhook-key",
            });
        }

        if !self.config.ca_file.exists() {
            return Err(WebhookError::MissingCredential {
                path: self.config.ca_file.clone(),
                component: "webhook-ca",
            });
        }

        let cert_pem = std::fs::read_to_string(&self.config.cert_file).map_err(|e| {
            WebhookError::AuthenticationFailed {
                reason: format!("failed to read cert file: {e}"),
            }
        })?;

        let ca_pem = std::fs::read_to_string(&self.config.ca_file).map_err(|e| {
            WebhookError::AuthenticationFailed {
                reason: format!("failed to read ca file: {e}"),
            }
        })?;

        diorama_pki::verify_certificate_chain(&cert_pem, &ca_pem).map_err(|e| {
            WebhookError::AuthenticationFailed {
                reason: format!("certificate chain verification failed: {e}"),
            }
        })?;

        let admin = self.apiserver.admin_client();
        admin
            .list_namespaces()
            .await
            .map_err(|e| WebhookError::AuthenticationFailed {
                reason: format!("failed to communicate with apiserver: {e}"),
            })?;

        Ok(())
    }

    /// Registers or updates the `MutatingWebhookConfiguration` on the apiserver and registers
    /// the in-process handler with `apiserver.admission()`.
    pub async fn register_webhook(&self) -> Result<(), WebhookError> {
        let mutating_config = self.config.create_configuration()?;
        let admin = self.apiserver.admin_client();

        let cert_pem = std::fs::read_to_string(&self.config.cert_file).ok();

        // 1. Register in-process endpoint with apiserver admission engine
        self.apiserver.admission().register_webhook_endpoint(
            DEFAULT_WEBHOOK_NAME,
            self.handler.clone(),
            cert_pem.clone(),
        );
        self.apiserver.admission().register_webhook_endpoint(
            &self.config.url,
            self.handler.clone(),
            cert_pem.clone(),
        );
        self.apiserver.admission().register_webhook_endpoint(
            "127.0.0.1",
            self.handler.clone(),
            cert_pem,
        );

        let config_val = serde_json::to_value(&mutating_config)?;

        // 2. Persist or update MutatingWebhookConfiguration via Kubernetes API
        match admin
            .get_mutating_webhook_configuration(DEFAULT_WEBHOOK_NAME)
            .await
        {
            Ok(_) => {
                admin
                    .update_mutating_webhook_configuration(DEFAULT_WEBHOOK_NAME, config_val)
                    .await?;
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                admin
                    .create_mutating_webhook_configuration(config_val)
                    .await?;
            },
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }

    /// Starts the webhook service, registers the configuration, and begins listening on the network.
    pub async fn start(&self) -> Result<(), WebhookError> {
        let _guard = self.lifecycle_lock.lock().await;
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.check_prerequisites().await?;
        self.register_webhook().await?;

        let addr = SocketAddr::new(self.config.bind_address, self.config.port);
        let listener = tokio::net::TcpListener::bind(addr).await?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        {
            let mut guard = self.shutdown_tx.lock().await;
            *guard = Some(shutdown_tx);
        }

        let handler = self.handler.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = WebhookServer::run_with_listener(listener, handler, shutdown_rx).await {
                eprintln!("webhook server error: {e}");
            }
        });
        {
            let mut guard = self.server_task.lock().await;
            *guard = Some(task);
        }

        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Checks the health and operational readiness of the webhook service.
    pub async fn check_readiness(&self) -> Result<WebhookHealthReport, WebhookError> {
        if !self.is_running() {
            return Ok(WebhookHealthReport::new_unhealthy(
                &self.config.url,
                "webhook service is not running",
            ));
        }

        let admin = self.apiserver.admin_client();
        if let Err(e) = admin
            .get_mutating_webhook_configuration(DEFAULT_WEBHOOK_NAME)
            .await
        {
            return Ok(WebhookHealthReport::new_unhealthy(
                &self.config.url,
                &format!("webhook configuration not found on apiserver: {e}"),
            ));
        }

        Ok(WebhookHealthReport::new_healthy(
            &self.config.url,
            self.config.load_balancer,
        ))
    }

    /// Stops the webhook service and awaits server task termination.
    pub async fn stop(&self) {
        let _guard = self.lifecycle_lock.lock().await;
        {
            let mut guard = self.shutdown_tx.lock().await;
            if let Some(tx) = guard.take() {
                let _ = tx.send(true);
            }
        }
        let task = {
            let mut guard = self.server_task.lock().await;
            guard.take()
        };
        if let Some(handle) = task {
            let _ = handle.await;
        }
        self.running.store(false, Ordering::SeqCst);
    }
}
