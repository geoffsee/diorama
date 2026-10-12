use std::time::{Duration, Instant};

use diorama_apiserver::client::KubernetesApiClient;
use diorama_apiserver::rbac::{
    ClusterRole as ApiserverClusterRole, ClusterRoleBinding as ApiserverClusterRoleBinding,
    PolicyRule as ApiserverPolicyRule, Role as ApiserverRole, RoleBinding as ApiserverRoleBinding,
    Subject as ApiserverSubject,
};
use tracing::{debug, info};

use crate::config::{
    LOCAL_PATH_CLUSTER_ROLE_BINDING_NAME, LOCAL_PATH_CLUSTER_ROLE_NAME, LOCAL_PATH_CONFIGMAP_NAME,
    LOCAL_PATH_DEPLOYMENT_NAME, LOCAL_PATH_NAMESPACE, LOCAL_PATH_ROLE_BINDING_NAME,
    LOCAL_PATH_ROLE_NAME, LOCAL_PATH_SERVICE_ACCOUNT_NAME, LOCAL_PATH_STORAGE_CLASS_NAME,
    LocalPathConfig,
};
use crate::error::{Result, StorageError};
use crate::manifests::{LocalPathManifests, generate_config_map_patch};

/// Summary of resources created, updated, or patched during reconciliation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconciliationReport {
    pub namespace_created: bool,
    pub service_account_created: bool,
    pub cluster_role_created: bool,
    pub cluster_role_updated: bool,
    pub cluster_role_binding_created: bool,
    pub cluster_role_binding_updated: bool,
    pub role_created: bool,
    pub role_updated: bool,
    pub role_binding_created: bool,
    pub role_binding_updated: bool,
    pub config_map_created: bool,
    pub config_map_patched: bool,
    pub storage_class_created: bool,
    pub storage_class_updated: bool,
    pub deployment_created: bool,
    pub deployment_updated: bool,
}

impl ReconciliationReport {
    /// Returns total number of resources created or updated.
    #[must_use]
    pub fn total_changes(&self) -> usize {
        let mut count = 0;
        if self.namespace_created {
            count += 1;
        }
        if self.service_account_created {
            count += 1;
        }
        if self.cluster_role_created || self.cluster_role_updated {
            count += 1;
        }
        if self.cluster_role_binding_created || self.cluster_role_binding_updated {
            count += 1;
        }
        if self.role_created || self.role_updated {
            count += 1;
        }
        if self.role_binding_created || self.role_binding_updated {
            count += 1;
        }
        if self.config_map_created || self.config_map_patched {
            count += 1;
        }
        if self.storage_class_created || self.storage_class_updated {
            count += 1;
        }
        if self.deployment_created || self.deployment_updated {
            count += 1;
        }
        count
    }
}

/// Idempotent reconciler for local-path storage provisioner resources.
#[derive(Clone, Debug)]
pub struct LocalPathReconciler {
    config: LocalPathConfig,
}

impl LocalPathReconciler {
    #[must_use]
    pub fn new(config: &LocalPathConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Reconciles all local-path storage manifests into Kubernetes in dependency order:
    /// 1. `Namespace` (created if absent)
    /// 2. `ServiceAccount` (created if absent)
    /// 3. `ClusterRole` (created or updated)
    /// 4. `ClusterRoleBinding` (created or updated)
    /// 5. `Role` (created or updated)
    /// 6. `RoleBinding` (created or updated)
    /// 7. `ConfigMap` (created or merge-patched)
    /// 8. `StorageClass` (created or updated)
    /// 9. `Deployment` (created or updated)
    ///
    /// If storage is disabled in configuration, reconciliation exits immediately with
    /// an empty report, ensuring disabled installations deploy/import no local-path components.
    pub async fn reconcile(&self, client: &KubernetesApiClient) -> Result<ReconciliationReport> {
        let mut report = ReconciliationReport::default();

        if !self.config.enabled {
            debug!("local-path storage is disabled; skipping manifest reconciliation");
            return Ok(report);
        }

        let manifests = LocalPathManifests::new(&self.config)?;

        // 1. Reconcile Namespace
        self.reconcile_namespace(client, &mut report).await?;

        // 2. Reconcile ServiceAccount
        self.reconcile_service_account(client, &manifests, &mut report)
            .await?;

        // 3. Reconcile ClusterRole and ClusterRoleBinding
        self.reconcile_cluster_rbac(client, &manifests, &mut report)
            .await?;

        // 4. Reconcile namespaced Role and RoleBinding
        self.reconcile_role_rbac(client, &manifests, &mut report)
            .await?;

        // 5. Reconcile ConfigMap
        self.reconcile_config_map(client, &manifests, &mut report)
            .await?;

        // 6. Reconcile StorageClass
        self.reconcile_storage_class(client, &manifests, &mut report)
            .await?;

        // 7. Reconcile Deployment
        self.reconcile_deployment(client, &manifests, &mut report)
            .await?;

        info!(
            "local-path storage reconciliation completed (total changes: {})",
            report.total_changes()
        );
        Ok(report)
    }

    async fn reconcile_namespace(
        &self,
        client: &KubernetesApiClient,
        report: &mut ReconciliationReport,
    ) -> Result<()> {
        match client.get_namespace(LOCAL_PATH_NAMESPACE).await {
            Ok(_) => {
                debug!("namespace {LOCAL_PATH_NAMESPACE} exists");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                client
                    .create_namespace(LOCAL_PATH_NAMESPACE)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.namespace_created = true;
                debug!("created namespace {LOCAL_PATH_NAMESPACE}");
            },
            Err(err) => return Err(StorageError::Apiserver(err)),
        }
        Ok(())
    }

    async fn reconcile_service_account(
        &self,
        client: &KubernetesApiClient,
        manifests: &LocalPathManifests,
        report: &mut ReconciliationReport,
    ) -> Result<()> {
        match client
            .get_service_account(LOCAL_PATH_NAMESPACE, LOCAL_PATH_SERVICE_ACCOUNT_NAME)
            .await
        {
            Ok(_) => {
                debug!("ServiceAccount {LOCAL_PATH_SERVICE_ACCOUNT_NAME} exists");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                let sa_val = serde_json::to_value(&manifests.service_account)?;
                client
                    .create_service_account(LOCAL_PATH_NAMESPACE, sa_val)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.service_account_created = true;
                debug!("created ServiceAccount {LOCAL_PATH_SERVICE_ACCOUNT_NAME}");
            },
            Err(err) => return Err(StorageError::Apiserver(err)),
        }
        Ok(())
    }

    async fn reconcile_cluster_rbac(
        &self,
        client: &KubernetesApiClient,
        manifests: &LocalPathManifests,
        report: &mut ReconciliationReport,
    ) -> Result<()> {
        let rules = manifests
            .cluster_role
            .rules
            .as_ref()
            .map(|r| r.iter().map(to_apiserver_policy_rule).collect())
            .unwrap_or_default();

        let cluster_role = ApiserverClusterRole {
            name: LOCAL_PATH_CLUSTER_ROLE_NAME.to_string(),
            rules,
        };

        match client.get_cluster_role(LOCAL_PATH_CLUSTER_ROLE_NAME).await {
            Ok(_) => {
                client
                    .update_cluster_role(cluster_role)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.cluster_role_updated = true;
                debug!("updated ClusterRole {LOCAL_PATH_CLUSTER_ROLE_NAME}");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                client
                    .create_cluster_role(cluster_role)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.cluster_role_created = true;
                debug!("created ClusterRole {LOCAL_PATH_CLUSTER_ROLE_NAME}");
            },
            Err(err) => return Err(StorageError::Apiserver(err)),
        }

        let cluster_role_binding = ApiserverClusterRoleBinding {
            name: LOCAL_PATH_CLUSTER_ROLE_BINDING_NAME.to_string(),
            role_ref: LOCAL_PATH_CLUSTER_ROLE_NAME.to_string(),
            subjects: vec![ApiserverSubject::ServiceAccount {
                namespace: LOCAL_PATH_NAMESPACE.to_string(),
                name: LOCAL_PATH_SERVICE_ACCOUNT_NAME.to_string(),
            }],
        };

        match client
            .get_cluster_role_binding(LOCAL_PATH_CLUSTER_ROLE_BINDING_NAME)
            .await
        {
            Ok(_) => {
                client
                    .update_cluster_role_binding(cluster_role_binding)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.cluster_role_binding_updated = true;
                debug!("updated ClusterRoleBinding {LOCAL_PATH_CLUSTER_ROLE_BINDING_NAME}");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                client
                    .create_cluster_role_binding(cluster_role_binding)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.cluster_role_binding_created = true;
                debug!("created ClusterRoleBinding {LOCAL_PATH_CLUSTER_ROLE_BINDING_NAME}");
            },
            Err(err) => return Err(StorageError::Apiserver(err)),
        }

        Ok(())
    }

    async fn reconcile_role_rbac(
        &self,
        client: &KubernetesApiClient,
        manifests: &LocalPathManifests,
        report: &mut ReconciliationReport,
    ) -> Result<()> {
        let rules = manifests
            .role
            .rules
            .as_ref()
            .map(|r| r.iter().map(to_apiserver_policy_rule).collect())
            .unwrap_or_default();

        let role = ApiserverRole {
            namespace: LOCAL_PATH_NAMESPACE.to_string(),
            name: LOCAL_PATH_ROLE_NAME.to_string(),
            rules,
        };

        match client
            .get_role(LOCAL_PATH_NAMESPACE, LOCAL_PATH_ROLE_NAME)
            .await
        {
            Ok(_) => {
                client
                    .update_role(role)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.role_updated = true;
                debug!("updated Role {LOCAL_PATH_ROLE_NAME}");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                client
                    .create_role(role)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.role_created = true;
                debug!("created Role {LOCAL_PATH_ROLE_NAME}");
            },
            Err(err) => return Err(StorageError::Apiserver(err)),
        }

        let role_binding = ApiserverRoleBinding {
            namespace: LOCAL_PATH_NAMESPACE.to_string(),
            name: LOCAL_PATH_ROLE_BINDING_NAME.to_string(),
            role_ref: LOCAL_PATH_ROLE_NAME.to_string(),
            subjects: vec![ApiserverSubject::ServiceAccount {
                namespace: LOCAL_PATH_NAMESPACE.to_string(),
                name: LOCAL_PATH_SERVICE_ACCOUNT_NAME.to_string(),
            }],
        };

        match client
            .get_role_binding(LOCAL_PATH_NAMESPACE, LOCAL_PATH_ROLE_BINDING_NAME)
            .await
        {
            Ok(_) => {
                client
                    .update_role_binding(role_binding)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.role_binding_updated = true;
                debug!("updated RoleBinding {LOCAL_PATH_ROLE_BINDING_NAME}");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                client
                    .create_role_binding(role_binding)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.role_binding_created = true;
                debug!("created RoleBinding {LOCAL_PATH_ROLE_BINDING_NAME}");
            },
            Err(err) => return Err(StorageError::Apiserver(err)),
        }

        Ok(())
    }

    async fn reconcile_config_map(
        &self,
        client: &KubernetesApiClient,
        manifests: &LocalPathManifests,
        report: &mut ReconciliationReport,
    ) -> Result<()> {
        match client
            .get_configmap(LOCAL_PATH_NAMESPACE, LOCAL_PATH_CONFIGMAP_NAME)
            .await
        {
            Ok(_) => {
                let patch = generate_config_map_patch(&manifests.config_map);
                client
                    .patch_configmap(LOCAL_PATH_NAMESPACE, LOCAL_PATH_CONFIGMAP_NAME, patch)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.config_map_patched = true;
                debug!("patched existing ConfigMap {LOCAL_PATH_CONFIGMAP_NAME}");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                let cm_val = serde_json::to_value(&manifests.config_map)?;
                client
                    .create_configmap_object(LOCAL_PATH_NAMESPACE, cm_val)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.config_map_created = true;
                debug!("created ConfigMap {LOCAL_PATH_CONFIGMAP_NAME}");
            },
            Err(err) => return Err(StorageError::Apiserver(err)),
        }
        Ok(())
    }

    async fn reconcile_storage_class(
        &self,
        client: &KubernetesApiClient,
        manifests: &LocalPathManifests,
        report: &mut ReconciliationReport,
    ) -> Result<()> {
        let sc_val = serde_json::to_value(&manifests.storage_class)?;
        match client
            .get_storage_class(LOCAL_PATH_STORAGE_CLASS_NAME)
            .await
        {
            Ok(_) => {
                client
                    .update_storage_class(LOCAL_PATH_STORAGE_CLASS_NAME, sc_val)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.storage_class_updated = true;
                debug!("updated StorageClass {LOCAL_PATH_STORAGE_CLASS_NAME}");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                client
                    .create_storage_class(sc_val)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.storage_class_created = true;
                debug!("created StorageClass {LOCAL_PATH_STORAGE_CLASS_NAME}");
            },
            Err(err) => return Err(StorageError::Apiserver(err)),
        }
        Ok(())
    }

    async fn reconcile_deployment(
        &self,
        client: &KubernetesApiClient,
        manifests: &LocalPathManifests,
        report: &mut ReconciliationReport,
    ) -> Result<()> {
        let dep_val = serde_json::to_value(&manifests.deployment)?;
        match client
            .get_deployment(LOCAL_PATH_NAMESPACE, LOCAL_PATH_DEPLOYMENT_NAME)
            .await
        {
            Ok(_) => {
                client
                    .update_deployment(LOCAL_PATH_NAMESPACE, LOCAL_PATH_DEPLOYMENT_NAME, dep_val)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.deployment_updated = true;
                debug!("updated Deployment {LOCAL_PATH_DEPLOYMENT_NAME}");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                client
                    .create_deployment(LOCAL_PATH_NAMESPACE, dep_val)
                    .await
                    .map_err(StorageError::Apiserver)?;
                report.deployment_created = true;
                debug!("created Deployment {LOCAL_PATH_DEPLOYMENT_NAME}");
            },
            Err(err) => return Err(StorageError::Apiserver(err)),
        }
        Ok(())
    }

    /// Waits for the `local-path-provisioner` deployment to report ready replicas.
    pub async fn wait_for_readiness(
        &self,
        client: &KubernetesApiClient,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let start = Instant::now();
        let mut attempts = 0;

        while start.elapsed() < timeout {
            attempts += 1;
            match client
                .get_deployment(LOCAL_PATH_NAMESPACE, LOCAL_PATH_DEPLOYMENT_NAME)
                .await
            {
                Ok(doc) => {
                    let ready = doc
                        .get("status")
                        .and_then(|s| s.get("readyReplicas"))
                        .and_then(serde_json::Value::as_i64)
                        .unwrap_or(0);

                    if ready > 0 {
                        debug!(
                            "local-path provisioner is ready with {ready} replica(s) after {attempts} attempts"
                        );
                        return Ok(());
                    }
                },
                Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                    // Deployment not yet visible; continue polling
                },
                Err(err) => return Err(StorageError::Apiserver(err)),
            }
            tokio::time::sleep(poll_interval).await;
        }

        Err(StorageError::ReadinessTimeout {
            elapsed: start.elapsed(),
            attempts,
        })
    }
}

fn to_apiserver_policy_rule(rule: &k8s_openapi::api::rbac::v1::PolicyRule) -> ApiserverPolicyRule {
    ApiserverPolicyRule {
        verbs: rule.verbs.clone(),
        api_groups: rule.api_groups.clone().unwrap_or_default(),
        resources: rule.resources.clone().unwrap_or_default(),
        resource_names: rule.resource_names.clone().unwrap_or_default(),
        non_resource_urls: rule.non_resource_urls.clone().unwrap_or_default(),
    }
}
