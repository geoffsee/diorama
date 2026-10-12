use std::time::Duration;

use diorama_apiserver::client::KubernetesApiClient;
use diorama_apiserver::error::ApiserverError;
use diorama_apiserver::rbac::{
    ClusterRoleBinding as ApiserverClusterRoleBinding, Subject as ApiserverSubject,
};
use serde_json::Value;
use tracing::{debug, info};

use crate::config::{
    CLUSTER_ADMIN_CLUSTER_ROLE_NAME, PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME,
    PORTAINER_AGENT_CONFIGMAP_NAME, PORTAINER_AGENT_DEPLOYMENT_NAME, PORTAINER_AGENT_SECRET_NAME,
    PORTAINER_AGENT_SERVICE_ACCOUNT_NAME, PORTAINER_AGENT_SERVICE_NAME, PORTAINER_NAMESPACE,
    PortainerAgentConfig,
};
use crate::error::{PortainerError, Result};
use crate::manifests::PortainerManifests;

/// Summary report of Portainer Edge agent resources created or preserved during reconciliation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortainerReconciliationReport {
    /// Whether the `portainer` Namespace was newly created.
    pub namespace_created: bool,
    /// Whether the existing `portainer` Namespace was preserved unchanged.
    pub namespace_preserved: bool,
    /// Whether the `portainer-sa-clusteradmin` `ServiceAccount` was newly created.
    pub service_account_created: bool,
    /// Whether the existing `portainer-sa-clusteradmin` `ServiceAccount` was preserved unchanged.
    pub service_account_preserved: bool,
    /// Whether the `portainer-crb-clusteradmin` `ClusterRoleBinding` was newly created.
    pub cluster_role_binding_created: bool,
    /// Whether the existing `portainer-crb-clusteradmin` `ClusterRoleBinding` was preserved unchanged.
    pub cluster_role_binding_preserved: bool,
    /// Whether the `portainer-agent-edge` `ConfigMap` was newly created.
    pub config_map_created: bool,
    /// Whether the existing `portainer-agent-edge` `ConfigMap` was preserved unchanged.
    pub config_map_preserved: bool,
    /// Whether the `portainer-agent-edge-key` Secret was newly created.
    pub secret_created: bool,
    /// Whether the existing `portainer-agent-edge-key` Secret was preserved unchanged.
    pub secret_preserved: bool,
    /// Whether the `portainer-agent` Service was newly created.
    pub service_created: bool,
    /// Whether the existing `portainer-agent` Service was preserved unchanged.
    pub service_preserved: bool,
    /// Whether the `portainer-agent` Deployment was newly created.
    pub deployment_created: bool,
    /// Whether the existing `portainer-agent` Deployment was preserved unchanged.
    pub deployment_preserved: bool,
}

impl PortainerReconciliationReport {
    /// Total count of newly created resources.
    #[must_use]
    pub fn total_created(&self) -> usize {
        usize::from(self.namespace_created)
            + usize::from(self.service_account_created)
            + usize::from(self.cluster_role_binding_created)
            + usize::from(self.config_map_created)
            + usize::from(self.secret_created)
            + usize::from(self.service_created)
            + usize::from(self.deployment_created)
    }

    /// Total count of preserved existing resources.
    #[must_use]
    pub fn total_preserved(&self) -> usize {
        usize::from(self.namespace_preserved)
            + usize::from(self.service_account_preserved)
            + usize::from(self.cluster_role_binding_preserved)
            + usize::from(self.config_map_preserved)
            + usize::from(self.secret_preserved)
            + usize::from(self.service_preserved)
            + usize::from(self.deployment_preserved)
    }

    /// Returns true if all 7 bootstrap resources are accounted for (created or preserved).
    #[must_use]
    pub fn all_retained(&self) -> bool {
        (self.namespace_created || self.namespace_preserved)
            && (self.service_account_created || self.service_account_preserved)
            && (self.cluster_role_binding_created || self.cluster_role_binding_preserved)
            && (self.config_map_created || self.config_map_preserved)
            && (self.secret_created || self.secret_preserved)
            && (self.service_created || self.service_preserved)
            && (self.deployment_created || self.deployment_preserved)
    }
}

/// Idempotent, create-only reconciler for Portainer Edge Agent Kubernetes resources.
///
/// Implements create-only bootstrap semantics:
/// - If a resource already exists in Kubernetes, it is preserved completely untouched.
///   No updates, patches, or replacements are performed.
/// - If a resource is missing, it is created deterministically from configuration.
/// - Concurrent creation conflict errors (`409 Conflict`) are treated as preserved.
#[derive(Clone, Debug)]
pub struct PortainerReconciler {
    config: PortainerAgentConfig,
}

impl PortainerReconciler {
    /// Create a new reconciler with the given Portainer agent configuration.
    #[must_use]
    pub fn new(config: &PortainerAgentConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Reconciles all Portainer Edge Agent manifests into Kubernetes in dependency order:
    /// 1. `Namespace` (`portainer`)
    /// 2. `ServiceAccount` (`portainer-sa-clusteradmin`)
    /// 3. `ClusterRoleBinding` (`portainer-crb-clusteradmin`)
    /// 4. `ConfigMap` (`portainer-agent-edge`)
    /// 5. `Secret` (`portainer-agent-edge-key`)
    /// 6. `Service` (`portainer-agent`)
    /// 7. `Deployment` (`portainer-agent`)
    ///
    /// Preserves existing resources without mutation and creates missing objects.
    pub async fn reconcile(
        &self,
        client: &KubernetesApiClient,
    ) -> Result<PortainerReconciliationReport> {
        if !self.config.is_architecture_supported() {
            return Err(PortainerError::UnsupportedArchitecture(
                self.config.architecture,
            ));
        }

        if self.config.has_missing_credentials() {
            return Err(PortainerError::MissingCredentials);
        }

        if self.config.has_partial_credentials() {
            return Err(PortainerError::IncompleteCredentials {
                has_id: !self.config.edge_id.is_empty(),
                has_key: !self.config.edge_key.is_empty(),
            });
        }

        let manifests = PortainerManifests::new(&self.config)?;
        let mut report = PortainerReconciliationReport::default();

        // 1. Reconcile Namespace
        self.reconcile_namespace(client, &mut report).await?;

        // 2. Reconcile ServiceAccount
        self.reconcile_service_account(client, &manifests, &mut report)
            .await?;

        // 3. Reconcile ClusterRoleBinding
        self.reconcile_cluster_role_binding(client, &mut report)
            .await?;

        // 4. Reconcile ConfigMap
        self.reconcile_config_map(client, &manifests, &mut report)
            .await?;

        // 5. Reconcile Secret
        self.reconcile_secret(client, &manifests, &mut report)
            .await?;

        // 6. Reconcile Service
        self.reconcile_service(client, &manifests, &mut report)
            .await?;

        // 7. Reconcile Deployment
        self.reconcile_deployment(client, &manifests, &mut report)
            .await?;

        info!(
            "Portainer reconciliation completed: {} created, {} preserved",
            report.total_created(),
            report.total_preserved()
        );
        Ok(report)
    }

    async fn reconcile_namespace(
        &self,
        client: &KubernetesApiClient,
        report: &mut PortainerReconciliationReport,
    ) -> Result<()> {
        match client.get_namespace(PORTAINER_NAMESPACE).await {
            Ok(_) => {
                report.namespace_preserved = true;
                debug!("namespace {PORTAINER_NAMESPACE} already exists; preserved");
            },
            Err(ApiserverError::NotFound { .. }) => {
                match client.create_namespace(PORTAINER_NAMESPACE).await {
                    Ok(_) => {
                        report.namespace_created = true;
                        debug!("created namespace {PORTAINER_NAMESPACE}");
                    },
                    Err(ApiserverError::Conflict { .. }) => {
                        report.namespace_preserved = true;
                        debug!("namespace {PORTAINER_NAMESPACE} created concurrently; preserved");
                    },
                    Err(e) => return Err(PortainerError::Apiserver(e)),
                }
            },
            Err(err) => return Err(PortainerError::Apiserver(err)),
        }
        Ok(())
    }

    async fn reconcile_service_account(
        &self,
        client: &KubernetesApiClient,
        manifests: &PortainerManifests,
        report: &mut PortainerReconciliationReport,
    ) -> Result<()> {
        match client
            .get_service_account(PORTAINER_NAMESPACE, PORTAINER_AGENT_SERVICE_ACCOUNT_NAME)
            .await
        {
            Ok(_) => {
                report.service_account_preserved = true;
                debug!(
                    "service account {PORTAINER_AGENT_SERVICE_ACCOUNT_NAME} already exists; preserved"
                );
            },
            Err(ApiserverError::NotFound { .. }) => {
                let sa_val = serde_json::to_value(&manifests.service_account)?;
                match client
                    .create_service_account(PORTAINER_NAMESPACE, sa_val)
                    .await
                {
                    Ok(_) => {
                        report.service_account_created = true;
                        debug!("created service account {PORTAINER_AGENT_SERVICE_ACCOUNT_NAME}");
                    },
                    Err(ApiserverError::Conflict { .. }) => {
                        report.service_account_preserved = true;
                        debug!(
                            "service account {PORTAINER_AGENT_SERVICE_ACCOUNT_NAME} created concurrently; preserved"
                        );
                    },
                    Err(e) => return Err(PortainerError::Apiserver(e)),
                }
            },
            Err(err) => return Err(PortainerError::Apiserver(err)),
        }
        Ok(())
    }

    async fn reconcile_cluster_role_binding(
        &self,
        client: &KubernetesApiClient,
        report: &mut PortainerReconciliationReport,
    ) -> Result<()> {
        let binding = ApiserverClusterRoleBinding {
            name: PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME.to_string(),
            role_ref: CLUSTER_ADMIN_CLUSTER_ROLE_NAME.to_string(),
            subjects: vec![ApiserverSubject::ServiceAccount {
                namespace: PORTAINER_NAMESPACE.to_string(),
                name: PORTAINER_AGENT_SERVICE_ACCOUNT_NAME.to_string(),
            }],
        };

        match client
            .get_cluster_role_binding(PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME)
            .await
        {
            Ok(_) => {
                report.cluster_role_binding_preserved = true;
                debug!(
                    "cluster role binding {PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME} already exists; preserved"
                );
            },
            Err(ApiserverError::NotFound { .. }) => {
                match client.create_cluster_role_binding(binding).await {
                    Ok(_) => {
                        report.cluster_role_binding_created = true;
                        debug!(
                            "created cluster role binding {PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME}"
                        );
                    },
                    Err(ApiserverError::Conflict { .. }) => {
                        report.cluster_role_binding_preserved = true;
                        debug!(
                            "cluster role binding {PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME} created concurrently; preserved"
                        );
                    },
                    Err(e) => return Err(PortainerError::Apiserver(e)),
                }
            },
            Err(err) => return Err(PortainerError::Apiserver(err)),
        }
        Ok(())
    }

    async fn reconcile_config_map(
        &self,
        client: &KubernetesApiClient,
        manifests: &PortainerManifests,
        report: &mut PortainerReconciliationReport,
    ) -> Result<()> {
        match client
            .get_configmap(PORTAINER_NAMESPACE, PORTAINER_AGENT_CONFIGMAP_NAME)
            .await
        {
            Ok(_) => {
                report.config_map_preserved = true;
                debug!("config map {PORTAINER_AGENT_CONFIGMAP_NAME} already exists; preserved");
            },
            Err(ApiserverError::NotFound { .. }) => {
                let cm_val = serde_json::to_value(&manifests.config_map)?;
                match client
                    .create_configmap_object(PORTAINER_NAMESPACE, cm_val)
                    .await
                {
                    Ok(_) => {
                        report.config_map_created = true;
                        debug!("created config map {PORTAINER_AGENT_CONFIGMAP_NAME}");
                    },
                    Err(ApiserverError::Conflict { .. }) => {
                        report.config_map_preserved = true;
                        debug!(
                            "config map {PORTAINER_AGENT_CONFIGMAP_NAME} created concurrently; preserved"
                        );
                    },
                    Err(e) => return Err(PortainerError::Apiserver(e)),
                }
            },
            Err(err) => return Err(PortainerError::Apiserver(err)),
        }
        Ok(())
    }

    async fn reconcile_secret(
        &self,
        client: &KubernetesApiClient,
        manifests: &PortainerManifests,
        report: &mut PortainerReconciliationReport,
    ) -> Result<()> {
        match client
            .get_secret(PORTAINER_NAMESPACE, PORTAINER_AGENT_SECRET_NAME)
            .await
        {
            Ok(_) => {
                report.secret_preserved = true;
                debug!("secret {PORTAINER_AGENT_SECRET_NAME} already exists; preserved");
            },
            Err(ApiserverError::NotFound { .. }) => {
                let secret_val = serde_json::to_value(&manifests.secret)?;
                match client
                    .create_secret_object(PORTAINER_NAMESPACE, secret_val)
                    .await
                {
                    Ok(_) => {
                        report.secret_created = true;
                        debug!("created secret {PORTAINER_AGENT_SECRET_NAME}");
                    },
                    Err(ApiserverError::Conflict { .. }) => {
                        report.secret_preserved = true;
                        debug!(
                            "secret {PORTAINER_AGENT_SECRET_NAME} created concurrently; preserved"
                        );
                    },
                    Err(e) => return Err(PortainerError::Apiserver(e)),
                }
            },
            Err(err) => return Err(PortainerError::Apiserver(err)),
        }
        Ok(())
    }

    async fn reconcile_service(
        &self,
        client: &KubernetesApiClient,
        manifests: &PortainerManifests,
        report: &mut PortainerReconciliationReport,
    ) -> Result<()> {
        match client
            .get_service(PORTAINER_NAMESPACE, PORTAINER_AGENT_SERVICE_NAME)
            .await
        {
            Ok(_) => {
                report.service_preserved = true;
                debug!("service {PORTAINER_AGENT_SERVICE_NAME} already exists; preserved");
            },
            Err(ApiserverError::NotFound { .. }) => {
                let svc_val = serde_json::to_value(&manifests.service)?;
                match client.create_service(PORTAINER_NAMESPACE, svc_val).await {
                    Ok(_) => {
                        report.service_created = true;
                        debug!("created service {PORTAINER_AGENT_SERVICE_NAME}");
                    },
                    Err(ApiserverError::Conflict { .. }) => {
                        report.service_preserved = true;
                        debug!(
                            "service {PORTAINER_AGENT_SERVICE_NAME} created concurrently; preserved"
                        );
                    },
                    Err(e) => return Err(PortainerError::Apiserver(e)),
                }
            },
            Err(err) => return Err(PortainerError::Apiserver(err)),
        }
        Ok(())
    }

    async fn reconcile_deployment(
        &self,
        client: &KubernetesApiClient,
        manifests: &PortainerManifests,
        report: &mut PortainerReconciliationReport,
    ) -> Result<()> {
        match client
            .get_deployment(PORTAINER_NAMESPACE, PORTAINER_AGENT_DEPLOYMENT_NAME)
            .await
        {
            Ok(_) => {
                report.deployment_preserved = true;
                debug!("deployment {PORTAINER_AGENT_DEPLOYMENT_NAME} already exists; preserved");
            },
            Err(ApiserverError::NotFound { .. }) => {
                let dep_val = serde_json::to_value(&manifests.deployment)?;
                match client.create_deployment(PORTAINER_NAMESPACE, dep_val).await {
                    Ok(_) => {
                        report.deployment_created = true;
                        debug!("created deployment {PORTAINER_AGENT_DEPLOYMENT_NAME}");
                    },
                    Err(ApiserverError::Conflict { .. }) => {
                        report.deployment_preserved = true;
                        debug!(
                            "deployment {PORTAINER_AGENT_DEPLOYMENT_NAME} created concurrently; preserved"
                        );
                    },
                    Err(e) => return Err(PortainerError::Apiserver(e)),
                }
            },
            Err(err) => return Err(PortainerError::Apiserver(err)),
        }
        Ok(())
    }

    /// Waits for the `portainer-agent` deployment to report ready replicas.
    ///
    /// If `timeout` is zero, immediately returns `Ok(())` without polling.
    pub async fn wait_for_readiness(
        &self,
        client: &KubernetesApiClient,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<()> {
        if timeout.is_zero() {
            return Ok(());
        }

        let start = std::time::Instant::now();
        let mut attempts = 0;

        let polling = async {
            loop {
                attempts += 1;
                let ready = match client
                    .get_deployment(PORTAINER_NAMESPACE, PORTAINER_AGENT_DEPLOYMENT_NAME)
                    .await
                {
                    Ok(doc) => doc
                        .get("status")
                        .and_then(|s| s.get("readyReplicas"))
                        .and_then(Value::as_i64)
                        .unwrap_or(0),
                    Err(ApiserverError::NotFound { .. }) => {
                        // Deployment not yet visible; continue polling.
                        0
                    },
                    Err(err) => return Err(PortainerError::Apiserver(err)),
                };
                if ready > 0 {
                    debug!(
                        "Portainer Edge agent is ready with {ready} replica(s) after {attempts} attempts"
                    );
                    return Ok(());
                }
                tokio::time::sleep(poll_interval).await;
            }
        };

        tokio::time::timeout(timeout, polling)
            .await
            .unwrap_or_else(|_| {
                Err(PortainerError::ReadinessTimeout {
                    elapsed: start.elapsed(),
                    attempts,
                })
            })
    }
}
