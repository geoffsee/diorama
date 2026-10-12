use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde_json::Value;

use crate::admission::AdmissionEngine;
use crate::aggregation::AggregationManager;
use crate::client::{ClientIdentity, KubernetesApiClient};
use crate::config::ApiserverConfig;
use crate::error::ApiserverError;
use crate::health::{HealthReport, check_apiserver_readiness};
use crate::logs::PodLogReader;
use crate::pki::validate_pki_prerequisites;
use crate::rbac::{ClusterRole, ClusterRoleBinding, RbacAuthorizer, Role, RoleBinding};
use crate::storage::KubernetesStorage;
use crate::token::{TokenProjection, TokenService};

#[derive(Clone, Debug)]
pub struct ApiserverService {
    config: ApiserverConfig,
    storage: KubernetesStorage,
    running: Arc<AtomicBool>,
    rbac: Arc<RbacAuthorizer>,
    token_service: Arc<RwLock<Option<TokenService>>>,
    admission: Arc<AdmissionEngine>,
    aggregation: Arc<AggregationManager>,
    crd_registry: Arc<RwLock<BTreeMap<String, Value>>>,
    bound_addr: Arc<Mutex<Option<SocketAddr>>>,
    pod_log_reader: Arc<RwLock<Option<Arc<dyn PodLogReader>>>>,
}

impl ApiserverService {
    pub fn new(config: ApiserverConfig, storage: KubernetesStorage) -> Self {
        let rbac = Arc::new(RbacAuthorizer::new());
        let token_service = Arc::new(RwLock::new(None));
        let admission = Arc::new(AdmissionEngine::new());
        let aggregation = Arc::new(AggregationManager::new());
        let crd_registry = Arc::new(RwLock::new(BTreeMap::new()));

        // Attempt early initialization of TokenService if key files already exist
        if config.service_account_signing_key_file.exists()
            && let Ok(ts) = TokenService::new(
                config.service_account_issuer.clone(),
                config.api_audiences.clone(),
                &config.service_account_signing_key_file,
                &config.service_account_key_file,
            )
        {
            let mut guard = token_service.write().unwrap();
            *guard = Some(ts);
        }

        Self {
            config,
            storage,
            running: Arc::new(AtomicBool::new(false)),
            rbac,
            token_service,
            admission,
            aggregation,
            crd_registry,
            bound_addr: Arc::new(Mutex::new(None)),
            pod_log_reader: Arc::new(RwLock::new(None)),
        }
    }

    #[must_use]
    pub fn config(&self) -> &ApiserverConfig {
        &self.config
    }

    #[must_use]
    pub fn storage(&self) -> &KubernetesStorage {
        &self.storage
    }

    #[must_use]
    pub fn rbac(&self) -> &Arc<RbacAuthorizer> {
        &self.rbac
    }

    #[must_use]
    pub fn admission(&self) -> &Arc<AdmissionEngine> {
        &self.admission
    }

    #[must_use]
    pub fn aggregation(&self) -> &Arc<AggregationManager> {
        &self.aggregation
    }

    #[must_use]
    pub fn crd_registry(&self) -> &Arc<RwLock<BTreeMap<String, Value>>> {
        &self.crd_registry
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn token_service(&self) -> Result<TokenService, ApiserverError> {
        {
            let guard = self.token_service.read().unwrap();
            if let Some(ts) = guard.as_ref() {
                return Ok(ts.clone());
            }
        }

        let ts = TokenService::new(
            self.config.service_account_issuer.clone(),
            self.config.api_audiences.clone(),
            &self.config.service_account_signing_key_file,
            &self.config.service_account_key_file,
        )?;

        let mut guard = self.token_service.write().unwrap();
        *guard = Some(ts.clone());
        Ok(ts)
    }

    fn token_service_opt(&self) -> Option<Arc<TokenService>> {
        self.token_service().ok().map(Arc::new)
    }

    /// Verifies all PKI and storage prerequisites before startup and initializes token service.
    pub async fn check_prerequisites(&self) -> Result<(), ApiserverError> {
        self.config.validate()?;
        validate_pki_prerequisites(&self.config)?;
        self.storage.check_health().await?;

        // Initialize TokenService
        let _ = self.token_service()?;

        // Restore persisted state from datastore
        self.restore_rbac_from_storage().await?;
        self.restore_crds_from_storage().await?;
        self.admission.restore_from_storage(&self.storage).await?;
        self.aggregation.restore_from_storage(&self.storage).await?;
        self.bootstrap_default_namespaces().await?;

        Ok(())
    }

    pub async fn bootstrap_default_namespaces(&self) -> Result<(), ApiserverError> {
        let admin = self.admin_client();
        for ns in ["default", "kube-system", "kube-node-lease"] {
            match admin.get_namespace(ns).await {
                Ok(_) => {},
                Err(ApiserverError::NotFound { .. }) => {
                    admin.create_namespace(ns).await?;
                },
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub async fn restore_crds_from_storage(&self) -> Result<(), ApiserverError> {
        let prefix = format!("{}/customresourcedefinitions", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut guard = self.crd_registry.write().unwrap();
        guard.clear();
        for kv in kvs {
            let crd: Value = serde_json::from_slice(&kv.value)?;
            if let Some(name) = crd
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            {
                guard.insert(name.to_string(), crd);
            }
        }
        Ok(())
    }

    /// Restores any customized `Roles`, `RoleBindings`, `ClusterRoles`, and `ClusterRoleBindings` from storage.
    pub async fn restore_rbac_from_storage(&self) -> Result<(), ApiserverError> {
        // 1. ClusterRoles
        let cluster_roles_prefix = format!("{}/clusterroles", self.storage.prefix());
        let cluster_roles_list = self.storage.list(&cluster_roles_prefix).await?;
        for kv in cluster_roles_list {
            let cr = serde_json::from_slice::<ClusterRole>(&kv.value).map_err(|e| {
                ApiserverError::StorageUnusable {
                    reason: format!("failed to deserialize ClusterRole at {}: {e}", kv.key),
                }
            })?;
            self.rbac.add_cluster_role(cr);
        }

        // 2. ClusterRoleBindings
        let cluster_bindings_prefix = format!("{}/clusterrolebindings", self.storage.prefix());
        let cluster_bindings_list = self.storage.list(&cluster_bindings_prefix).await?;
        for kv in cluster_bindings_list {
            let crb = serde_json::from_slice::<ClusterRoleBinding>(&kv.value).map_err(|e| {
                ApiserverError::StorageUnusable {
                    reason: format!(
                        "failed to deserialize ClusterRoleBinding at {}: {e}",
                        kv.key
                    ),
                }
            })?;
            self.rbac.add_cluster_role_binding(crb);
        }

        // 3. Roles
        let namespaced_roles_prefix = format!("{}/roles", self.storage.prefix());
        let namespaced_roles_list = self.storage.list(&namespaced_roles_prefix).await?;
        for kv in namespaced_roles_list {
            let r = serde_json::from_slice::<Role>(&kv.value).map_err(|e| {
                ApiserverError::StorageUnusable {
                    reason: format!("failed to deserialize Role at {}: {e}", kv.key),
                }
            })?;
            self.rbac.add_role(r);
        }

        // 4. RoleBindings
        let namespaced_bindings_prefix = format!("{}/rolebindings", self.storage.prefix());
        let namespaced_bindings_list = self.storage.list(&namespaced_bindings_prefix).await?;
        for kv in namespaced_bindings_list {
            let rb = serde_json::from_slice::<RoleBinding>(&kv.value).map_err(|e| {
                ApiserverError::StorageUnusable {
                    reason: format!("failed to deserialize RoleBinding at {}: {e}", kv.key),
                }
            })?;
            self.rbac.add_role_binding(rb);
        }

        Ok(())
    }

    /// Evaluates current operational readiness.
    pub async fn check_readiness(&self) -> Result<HealthReport, ApiserverError> {
        check_apiserver_readiness(&self.config, &self.storage).await
    }

    pub fn start(&self) -> Result<(), ApiserverError> {
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub(crate) fn set_bound_addr(&self, addr: SocketAddr) {
        *self.bound_addr.lock().unwrap() = Some(addr);
    }

    /// Address of the HTTPS listener once the supervisor has bound it.
    #[must_use]
    pub fn bound_addr(&self) -> Option<SocketAddr> {
        *self.bound_addr.lock().unwrap()
    }

    /// Registers the in-process kubelet as the source for the pod log subresource.
    pub fn set_pod_log_reader(&self, reader: Arc<dyn PodLogReader>) {
        *self.pod_log_reader.write().unwrap() = Some(reader);
    }

    /// The pod log source, if a kubelet has registered one.
    #[must_use]
    pub fn pod_log_reader(&self) -> Option<Arc<dyn PodLogReader>> {
        self.pod_log_reader.read().unwrap().clone()
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    // --- Service Account Token Issuance & Projection ---

    pub fn issue_service_account_token(
        &self,
        namespace: &str,
        name: &str,
        audiences: &[String],
        lifetime: Duration,
    ) -> Result<String, ApiserverError> {
        let ts = self.token_service()?;
        ts.issue_token(namespace, name, "sa-uid-default", audiences, lifetime)
    }

    pub fn project_service_account_token(
        &self,
        target_dir: &Path,
        namespace: &str,
        name: &str,
        audiences: &[String],
        lifetime: Duration,
    ) -> Result<PathBuf, ApiserverError> {
        let ts = self.token_service()?;
        let ca_cert = if self.config.client_ca_file.exists() {
            fs::read(&self.config.client_ca_file).unwrap_or_default()
        } else {
            Vec::new()
        };
        let projection = TokenProjection {
            target_dir,
            namespace,
            sa_name: name,
            sa_uid: "sa-uid-default",
            audiences,
            lifetime,
            ca_cert: &ca_cert,
        };
        ts.project_token_volume(&projection)
    }

    // --- Client Factory ---

    fn create_client(&self, identity: ClientIdentity) -> KubernetesApiClient {
        KubernetesApiClient::new(
            self.storage.clone(),
            identity,
            self.rbac.clone(),
            self.token_service_opt(),
            self.admission.clone(),
            self.aggregation.clone(),
            self.crd_registry.clone(),
            &self.config,
        )
    }

    #[must_use]
    pub fn admin_client(&self) -> KubernetesApiClient {
        self.create_client(ClientIdentity::AdminCertificate)
    }

    #[must_use]
    pub fn anonymous_client(&self) -> KubernetesApiClient {
        self.create_client(ClientIdentity::Anonymous)
    }

    #[must_use]
    pub fn token_client(&self, token: impl Into<String>) -> KubernetesApiClient {
        self.create_client(ClientIdentity::BearerToken(token.into()))
    }

    #[must_use]
    pub fn service_account_client(
        &self,
        namespace: impl Into<String>,
        name: impl Into<String>,
    ) -> KubernetesApiClient {
        self.create_client(ClientIdentity::ServiceAccount {
            namespace: namespace.into(),
            name: name.into(),
        })
    }

    #[must_use]
    pub fn controller_manager_client(&self) -> KubernetesApiClient {
        self.create_client(ClientIdentity::User {
            username: "system:kube-controller-manager".to_string(),
            groups: vec!["system:authenticated".to_string()],
        })
    }

    #[must_use]
    pub fn scheduler_client(&self) -> KubernetesApiClient {
        self.create_client(ClientIdentity::User {
            username: "system:kube-scheduler".to_string(),
            groups: vec!["system:authenticated".to_string()],
        })
    }

    #[must_use]
    pub fn node_client(&self, node_name: &str) -> KubernetesApiClient {
        self.create_client(ClientIdentity::User {
            username: format!("system:node:{node_name}"),
            groups: vec![
                "system:nodes".to_string(),
                "system:authenticated".to_string(),
            ],
        })
    }

    #[must_use]
    pub fn user_client(
        &self,
        username: impl Into<String>,
        groups: Vec<String>,
    ) -> KubernetesApiClient {
        self.create_client(ClientIdentity::User {
            username: username.into(),
            groups,
        })
    }

    #[must_use]
    pub fn restricted_client(
        &self,
        username: impl Into<String>,
        groups: Vec<String>,
    ) -> KubernetesApiClient {
        self.create_client(ClientIdentity::RestrictedUser {
            username: username.into(),
            groups,
        })
    }

    #[must_use]
    pub fn front_proxy_client(
        &self,
        client_cert_pem: impl Into<String>,
        username: impl Into<String>,
        groups: Vec<String>,
    ) -> KubernetesApiClient {
        self.create_client(ClientIdentity::FrontProxy {
            client_cert_pem: client_cert_pem.into(),
            username: username.into(),
            groups,
        })
    }
}
