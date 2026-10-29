use std::time::{Duration, Instant};

use diorama_apiserver::client::KubernetesApiClient;
use diorama_apiserver::rbac::{
    ClusterRole as ApiserverClusterRole, ClusterRoleBinding as ApiserverClusterRoleBinding,
    PolicyRule, Subject,
};
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use crate::config::{
    COREDNS_CLUSTER_ROLE_NAME, COREDNS_CONFIGMAP_NAME, COREDNS_DEPLOYMENT_NAME, COREDNS_NAMESPACE,
    COREDNS_SERVICE_ACCOUNT_NAME, COREDNS_SERVICE_NAME, CoreDnsConfig,
};
use crate::error::{DnsError, Result};
use crate::manifests::{coredns_labels, coredns_selector, generate_config_map_patch};

/// Summary of resources created, updated, or patched during reconciliation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconciliationReport {
    pub config_map_created: bool,
    pub config_map_patched: bool,
    pub service_account_created: bool,
    pub cluster_role_created: bool,
    pub cluster_role_updated: bool,
    pub cluster_role_binding_created: bool,
    pub cluster_role_binding_updated: bool,
    pub service_created: bool,
    pub service_recreated: bool,
    pub service_updated: bool,
    pub deployment_created: bool,
    pub deployment_updated: bool,
}

/// Idempotent reconciler for all `CoreDNS` resources.
#[derive(Clone, Debug)]
pub struct DnsReconciler {
    config: CoreDnsConfig,
}

impl DnsReconciler {
    #[must_use]
    pub fn new(config: &CoreDnsConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Reconciles all `CoreDNS` manifests into Kubernetes in dependency order:
    /// 1. `ConfigMap` (created or merge-patched to preserve unrelated keys/metadata)
    /// 2. `ServiceAccount` (created if absent)
    /// 3. `ClusterRole` (created or updated)
    /// 4. `ClusterRoleBinding` (created or updated)
    /// 5. `Service` (created, recreated if `ClusterIP` changed, or updated)
    /// 6. `Deployment` (created or updated)
    pub async fn reconcile(&self, client: &KubernetesApiClient) -> Result<ReconciliationReport> {
        let mut report = ReconciliationReport::default();

        // 1. Reconcile ConfigMap
        self.reconcile_config_map(client, &mut report).await?;

        // 2. Reconcile ServiceAccount
        self.reconcile_service_account(client, &mut report).await?;

        // 3. Reconcile RBAC (ClusterRole and ClusterRoleBinding)
        self.reconcile_rbac(client, &mut report).await?;

        // 4. Reconcile Service
        self.reconcile_service(client, &mut report).await?;

        // 5. Reconcile Deployment
        self.reconcile_deployment(client, &mut report).await?;

        Ok(report)
    }

    async fn reconcile_config_map(
        &self,
        client: &KubernetesApiClient,
        report: &mut ReconciliationReport,
    ) -> Result<()> {
        let corefile = self.config.generate_corefile();
        match client
            .get_configmap(COREDNS_NAMESPACE, COREDNS_CONFIGMAP_NAME)
            .await
        {
            Ok(_) => {
                let patch = generate_config_map_patch(&corefile);
                client
                    .patch_configmap(COREDNS_NAMESPACE, COREDNS_CONFIGMAP_NAME, patch)
                    .await?;
                report.config_map_patched = true;
                debug!("patched existing CoreDNS ConfigMap preserving unrelated keys");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                let cm_value = json!({
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {
                        "name": COREDNS_CONFIGMAP_NAME,
                        "namespace": COREDNS_NAMESPACE,
                    },
                    "data": {
                        "Corefile": corefile,
                    }
                });
                client
                    .create_configmap_object(COREDNS_NAMESPACE, cm_value)
                    .await?;
                report.config_map_created = true;
                debug!("created CoreDNS ConfigMap");
            },
            Err(err) => return Err(DnsError::Apiserver(err)),
        }
        Ok(())
    }

    async fn reconcile_service_account(
        &self,
        client: &KubernetesApiClient,
        report: &mut ReconciliationReport,
    ) -> Result<()> {
        match client
            .get_service_account(COREDNS_NAMESPACE, COREDNS_SERVICE_ACCOUNT_NAME)
            .await
        {
            Ok(_) => {
                debug!("CoreDNS ServiceAccount already exists");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                let sa_value = json!({
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {
                        "name": COREDNS_SERVICE_ACCOUNT_NAME,
                        "namespace": COREDNS_NAMESPACE,
                    }
                });
                client
                    .create_service_account(COREDNS_NAMESPACE, sa_value)
                    .await?;
                report.service_account_created = true;
                debug!("created CoreDNS ServiceAccount");
            },
            Err(err) => return Err(DnsError::Apiserver(err)),
        }
        Ok(())
    }

    async fn reconcile_rbac(
        &self,
        client: &KubernetesApiClient,
        report: &mut ReconciliationReport,
    ) -> Result<()> {
        let cluster_role = ApiserverClusterRole {
            name: COREDNS_CLUSTER_ROLE_NAME.to_string(),
            rules: vec![
                PolicyRule {
                    verbs: vec!["list".to_string(), "watch".to_string()],
                    api_groups: vec![String::new()],
                    resources: vec![
                        "endpoints".to_string(),
                        "services".to_string(),
                        "pods".to_string(),
                        "namespaces".to_string(),
                    ],
                    resource_names: Vec::new(),
                    non_resource_urls: Vec::new(),
                },
                PolicyRule {
                    verbs: vec!["list".to_string(), "watch".to_string()],
                    api_groups: vec!["discovery.k8s.io".to_string()],
                    resources: vec!["endpointslices".to_string()],
                    resource_names: Vec::new(),
                    non_resource_urls: Vec::new(),
                },
            ],
        };

        match client.get_cluster_role(COREDNS_CLUSTER_ROLE_NAME).await {
            Ok(_) => {
                client.update_cluster_role(cluster_role).await?;
                report.cluster_role_updated = true;
                debug!("updated CoreDNS ClusterRole");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                client.create_cluster_role(cluster_role).await?;
                report.cluster_role_created = true;
                debug!("created CoreDNS ClusterRole");
            },
            Err(err) => return Err(DnsError::Apiserver(err)),
        }

        let cluster_role_binding = ApiserverClusterRoleBinding {
            name: COREDNS_CLUSTER_ROLE_NAME.to_string(),
            role_ref: COREDNS_CLUSTER_ROLE_NAME.to_string(),
            subjects: vec![Subject::ServiceAccount {
                namespace: COREDNS_NAMESPACE.to_string(),
                name: COREDNS_SERVICE_ACCOUNT_NAME.to_string(),
            }],
        };

        match client
            .get_cluster_role_binding(COREDNS_CLUSTER_ROLE_NAME)
            .await
        {
            Ok(_) => {
                client
                    .update_cluster_role_binding(cluster_role_binding)
                    .await?;
                report.cluster_role_binding_updated = true;
                debug!("updated CoreDNS ClusterRoleBinding");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                client
                    .create_cluster_role_binding(cluster_role_binding)
                    .await?;
                report.cluster_role_binding_created = true;
                debug!("created CoreDNS ClusterRoleBinding");
            },
            Err(err) => return Err(DnsError::Apiserver(err)),
        }

        Ok(())
    }

    async fn reconcile_service(
        &self,
        client: &KubernetesApiClient,
        report: &mut ReconciliationReport,
    ) -> Result<()> {
        let desired_val = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": COREDNS_SERVICE_NAME,
                "namespace": COREDNS_NAMESPACE,
                "labels": coredns_labels(),
            },
            "spec": {
                "clusterIP": self.config.dns_ip,
                "selector": coredns_selector(),
                "ports": [
                    {
                        "name": "dns",
                        "port": 53,
                        "protocol": "UDP",
                        "targetPort": 0,
                    },
                    {
                        "name": "dns-tcp",
                        "port": 53,
                        "protocol": "TCP",
                        "targetPort": 0,
                    }
                ]
            }
        });
        match client
            .get_service(COREDNS_NAMESPACE, COREDNS_SERVICE_NAME)
            .await
        {
            Ok(existing_val) => {
                let desired_cluster_ip = Some(self.config.dns_ip.as_str());
                let recreate = existing_val
                    .get("spec")
                    .and_then(Value::as_object)
                    .is_none_or(|existing_spec| {
                        existing_spec.get("clusterIP").and_then(Value::as_str) != desired_cluster_ip
                    });
                if recreate {
                    warn!("CoreDNS service ClusterIP changed; deleting and recreating Service");
                    client
                        .delete_service(COREDNS_NAMESPACE, COREDNS_SERVICE_NAME)
                        .await?;
                    client
                        .create_service(COREDNS_NAMESPACE, desired_val)
                        .await?;
                    report.service_recreated = true;
                } else {
                    let mut desired_svc_val = desired_val;
                    merge_service_metadata(&mut desired_svc_val, &existing_val);
                    client
                        .update_service(COREDNS_NAMESPACE, COREDNS_SERVICE_NAME, desired_svc_val)
                        .await?;
                    report.service_updated = true;
                    debug!("updated CoreDNS Service in-place");
                }
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                client
                    .create_service(COREDNS_NAMESPACE, desired_val)
                    .await?;
                report.service_created = true;
                debug!("created CoreDNS Service");
            },
            Err(err) => return Err(DnsError::Apiserver(err)),
        }
        Ok(())
    }

    fn desired_deployment_value(&self) -> serde_json::Value {
        let mut resources = json!({
            "requests": {
                "cpu": "50m",
                "memory": "20Mi",
            }
        });
        if !self.config.container_mode {
            resources["limits"] = json!({ "memory": "64Mi" });
        }
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": COREDNS_DEPLOYMENT_NAME,
                "namespace": COREDNS_NAMESPACE,
                "labels": coredns_labels(),
            },
            "spec": {
                "replicas": 1,
                "strategy": {
                    "type": "RollingUpdate",
                    "rollingUpdate": {
                        "maxUnavailable": 1,
                    }
                },
                "selector": {
                    "matchLabels": coredns_selector(),
                },
                "template": {
                    "metadata": {
                        "labels": coredns_selector(),
                    },
                    "spec": {
                        "dnsPolicy": "Default",
                        "priorityClassName": "system-cluster-critical",
                        "nodeSelector": {"diorama.io/runtime":"ordinary"},
                        "serviceAccountName": COREDNS_SERVICE_ACCOUNT_NAME,
                        "containers": [{
                            "name": "coredns",
                            "image": self.config.image,
                            "imagePullPolicy": "IfNotPresent",
                            "resources": resources,
                            "args": ["-conf", "/etc/coredns/Corefile"],
                            "volumeMounts": [{
                                "name": "config-volume",
                                "mountPath": "/etc/coredns",
                            }],
                            "ports": [
                                { "containerPort": 53, "name": "dns", "protocol": "UDP" },
                                { "containerPort": 53, "name": "dns-tcp", "protocol": "TCP" },
                                { "containerPort": 8080, "name": "metrics", "protocol": "TCP" },
                            ],
                            "livenessProbe": {
                                "httpGet": { "path": "/health", "port": 8080, "scheme": "HTTP" },
                                "initialDelaySeconds": 60,
                                "periodSeconds": 10,
                                "successThreshold": 1,
                                "timeoutSeconds": 5,
                                "failureThreshold": 3,
                            },
                            "readinessProbe": {
                                "httpGet": { "path": "/ready", "port": 8181, "scheme": "HTTP" },
                                "initialDelaySeconds": 10,
                                "periodSeconds": 10,
                                "successThreshold": 1,
                                "timeoutSeconds": 5,
                                "failureThreshold": 3,
                            },
                        }],
                        "volumes": [{
                            "name": "config-volume",
                            "configMap": {
                                "name": COREDNS_CONFIGMAP_NAME,
                                "items": [{ "key": "Corefile", "path": "Corefile" }],
                            }
                        }],
                    }
                }
            }
        })
    }

    async fn reconcile_deployment(
        &self,
        client: &KubernetesApiClient,
        report: &mut ReconciliationReport,
    ) -> Result<()> {
        let mut desired_val = self.desired_deployment_value();
        match client
            .get_deployment(COREDNS_NAMESPACE, COREDNS_DEPLOYMENT_NAME)
            .await
        {
            Ok(existing_val) => {
                if let Some(existing_status) = existing_val.get("status").filter(|s| !s.is_null()) {
                    desired_val["status"] = existing_status.clone();
                }
                client
                    .update_deployment(COREDNS_NAMESPACE, COREDNS_DEPLOYMENT_NAME, desired_val)
                    .await?;
                report.deployment_updated = true;
                debug!("updated CoreDNS Deployment");
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                client
                    .create_deployment(COREDNS_NAMESPACE, desired_val)
                    .await?;
                report.deployment_created = true;
                debug!("created CoreDNS Deployment");
            },
            Err(err) => return Err(DnsError::Apiserver(err)),
        }
        Ok(())
    }

    /// Polls the `CoreDNS` deployment until at least one replica is ready or timeout occurs.
    pub async fn wait_for_readiness(
        &self,
        client: &KubernetesApiClient,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<()> {
        info!(
            timeout_secs = timeout.as_secs(),
            "waiting for CoreDNS deployment readiness"
        );
        let start = Instant::now();
        let mut attempts = 0u32;

        while start.elapsed() < timeout {
            attempts += 1;
            match client
                .get_deployment(COREDNS_NAMESPACE, COREDNS_DEPLOYMENT_NAME)
                .await
            {
                Ok(doc) => {
                    let ready_replicas = doc
                        .get("status")
                        .and_then(|s| s.get("readyReplicas"))
                        .and_then(serde_json::Value::as_i64)
                        .unwrap_or(0);

                    if ready_replicas > 0 {
                        info!(
                            ready_replicas,
                            elapsed_ms = start.elapsed().as_millis(),
                            attempts,
                            "CoreDNS is ready"
                        );
                        return Ok(());
                    }
                    debug!(
                        ready_replicas,
                        attempt = attempts,
                        "CoreDNS not ready yet, waiting..."
                    );
                },
                Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                    debug!(
                        attempt = attempts,
                        "CoreDNS deployment not yet found, waiting..."
                    );
                },
                Err(err) => {
                    warn!(error = %err, attempt = attempts, "error polling CoreDNS deployment");
                },
            }

            tokio::time::sleep(poll_interval).await;
        }

        Err(DnsError::ReadinessTimeout {
            elapsed: start.elapsed(),
            attempts,
        })
    }
}

/// Merges custom metadata (labels, annotations, creationTimestamp) from an existing Service
/// into the desired Service value to preserve user/operator modifications during in-place updates.
fn merge_service_metadata(desired: &mut Value, existing: &Value) {
    let Some(existing_meta) = existing.get("metadata").and_then(Value::as_object) else {
        return;
    };
    let Some(desired_meta) = desired.get_mut("metadata").and_then(Value::as_object_mut) else {
        return;
    };

    if let Some(existing_labels) = existing_meta.get("labels").and_then(Value::as_object) {
        let labels = desired_meta
            .entry("labels".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut();
        if let Some(labels_map) = labels {
            for (k, v) in existing_labels {
                if !labels_map.contains_key(k) {
                    labels_map.insert(k.clone(), v.clone());
                }
            }
        }
    }

    if let Some(existing_annotations) = existing_meta.get("annotations").and_then(Value::as_object)
    {
        let annotations = desired_meta
            .entry("annotations".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut();
        if let Some(ann_map) = annotations {
            for (k, v) in existing_annotations {
                if !ann_map.contains_key(k) {
                    ann_map.insert(k.clone(), v.clone());
                }
            }
        }
    }

    if let Some(creation_ts) = existing_meta.get("creationTimestamp") {
        desired_meta.insert("creationTimestamp".to_string(), creation_ts.clone());
    }
}
