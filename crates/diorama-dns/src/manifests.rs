use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{
    Deployment, DeploymentSpec, DeploymentStrategy, RollingUpdateDeployment,
};
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, HTTPGetAction, KeyToPath, PodSpec,
    PodTemplateSpec, Probe, ResourceRequirements, Service, ServiceAccount, ServicePort,
    ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, PolicyRule, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

use crate::config::{
    COREDNS_CLUSTER_ROLE_NAME, COREDNS_CONFIGMAP_NAME, COREDNS_DEPLOYMENT_NAME, COREDNS_NAMESPACE,
    COREDNS_SERVICE_ACCOUNT_NAME, COREDNS_SERVICE_NAME, CoreDnsConfig,
};

/// All `CoreDNS` manifests bundled for creation and reconciliation.
#[derive(Debug, Clone, PartialEq)]
pub struct CoreDnsManifests {
    pub service_account: ServiceAccount,
    pub cluster_role: ClusterRole,
    pub cluster_role_binding: ClusterRoleBinding,
    pub config_map: ConfigMap,
    pub service: Service,
    pub deployment: Deployment,
}

impl CoreDnsManifests {
    /// Generate all `CoreDNS` manifests for the given configuration.
    #[must_use]
    pub fn new(config: &CoreDnsConfig) -> Self {
        Self {
            service_account: generate_service_account(COREDNS_NAMESPACE),
            cluster_role: generate_cluster_role(),
            cluster_role_binding: generate_cluster_role_binding(COREDNS_NAMESPACE),
            config_map: generate_config_map(config, COREDNS_NAMESPACE),
            service: generate_service(config, COREDNS_NAMESPACE),
            deployment: generate_deployment(config, COREDNS_NAMESPACE),
        }
    }
}

/// Standard labels applied to `CoreDNS` workload and service objects.
#[must_use]
pub fn coredns_labels() -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("k8s-app".to_string(), "coredns".to_string());
    labels.insert("kubernetes.io/name".to_string(), "CoreDNS".to_string());
    labels
}

/// Selector labels matching `CoreDNS` pods.
#[must_use]
pub fn coredns_selector() -> BTreeMap<String, String> {
    let mut selector = BTreeMap::new();
    selector.insert("k8s-app".to_string(), "coredns".to_string());
    selector
}

/// Generate the `ServiceAccount` in `kube-system`.
#[must_use]
pub fn generate_service_account(namespace: &str) -> ServiceAccount {
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some(COREDNS_SERVICE_ACCOUNT_NAME.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Generate the `ClusterRole` with discovery and pod/service listing permissions.
#[must_use]
pub fn generate_cluster_role() -> ClusterRole {
    ClusterRole {
        metadata: ObjectMeta {
            name: Some(COREDNS_CLUSTER_ROLE_NAME.to_string()),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec![
                    "endpoints".to_string(),
                    "services".to_string(),
                    "pods".to_string(),
                    "namespaces".to_string(),
                ]),
                verbs: vec!["list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["discovery.k8s.io".to_string()]),
                resources: Some(vec!["endpointslices".to_string()]),
                verbs: vec!["list".to_string(), "watch".to_string()],
                ..Default::default()
            },
        ]),
        ..Default::default()
    }
}

/// Generate the `ClusterRoleBinding` binding `system:coredns` to `ServiceAccount/coredns`.
#[must_use]
pub fn generate_cluster_role_binding(namespace: &str) -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(COREDNS_CLUSTER_ROLE_NAME.to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: COREDNS_CLUSTER_ROLE_NAME.to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: COREDNS_SERVICE_ACCOUNT_NAME.to_string(),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        }]),
    }
}

/// Generate the `ConfigMap` holding the Corefile.
#[must_use]
pub fn generate_config_map(config: &CoreDnsConfig, namespace: &str) -> ConfigMap {
    let mut data = BTreeMap::new();
    data.insert("Corefile".to_string(), config.generate_corefile());

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(COREDNS_CONFIGMAP_NAME.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

/// Generate the `kube-dns` `Service`.
#[must_use]
pub fn generate_service(config: &CoreDnsConfig, namespace: &str) -> Service {
    Service {
        metadata: ObjectMeta {
            name: Some(COREDNS_SERVICE_NAME.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(coredns_labels()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            cluster_ip: Some(config.dns_ip.clone()),
            selector: Some(coredns_selector()),
            ports: Some(vec![
                ServicePort {
                    name: Some("dns".to_string()),
                    port: 53,
                    protocol: Some("UDP".to_string()),
                    target_port: Some(IntOrString::Int(0)),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("dns-tcp".to_string()),
                    port: 53,
                    protocol: Some("TCP".to_string()),
                    target_port: Some(IntOrString::Int(0)),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        status: None,
    }
}

/// Generate the `coredns` `Deployment`.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn generate_deployment(config: &CoreDnsConfig, namespace: &str) -> Deployment {
    let mut requests = BTreeMap::new();
    requests.insert("cpu".to_string(), Quantity("50m".to_string()));
    requests.insert("memory".to_string(), Quantity("20Mi".to_string()));

    let limits = if config.container_mode {
        None
    } else {
        let mut limits = BTreeMap::new();
        limits.insert("memory".to_string(), Quantity("64Mi".to_string()));
        Some(limits)
    };

    let resources = ResourceRequirements {
        claims: None,
        limits,
        requests: Some(requests),
    };

    Deployment {
        metadata: ObjectMeta {
            name: Some(COREDNS_DEPLOYMENT_NAME.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(coredns_labels()),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            strategy: Some(DeploymentStrategy {
                type_: Some("RollingUpdate".to_string()),
                rolling_update: Some(RollingUpdateDeployment {
                    max_unavailable: Some(IntOrString::Int(1)),
                    max_surge: None,
                }),
            }),
            selector: LabelSelector {
                match_labels: Some(coredns_selector()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(coredns_selector()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    dns_policy: Some("Default".to_string()),
                    priority_class_name: Some("system-cluster-critical".to_string()),
                    service_account_name: Some(COREDNS_SERVICE_ACCOUNT_NAME.to_string()),
                    containers: vec![Container {
                        name: "coredns".to_string(),
                        image: Some(config.image.clone()),
                        image_pull_policy: Some("IfNotPresent".to_string()),
                        resources: Some(resources),
                        args: Some(vec![
                            "-conf".to_string(),
                            "/etc/coredns/Corefile".to_string(),
                        ]),
                        volume_mounts: Some(vec![VolumeMount {
                            name: "config-volume".to_string(),
                            mount_path: "/etc/coredns".to_string(),
                            ..Default::default()
                        }]),
                        ports: Some(vec![
                            ContainerPort {
                                container_port: 53,
                                name: Some("dns".to_string()),
                                protocol: Some("UDP".to_string()),
                                ..Default::default()
                            },
                            ContainerPort {
                                container_port: 53,
                                name: Some("dns-tcp".to_string()),
                                protocol: Some("TCP".to_string()),
                                ..Default::default()
                            },
                            ContainerPort {
                                container_port: 8080,
                                name: Some("metrics".to_string()),
                                protocol: Some("TCP".to_string()),
                                ..Default::default()
                            },
                        ]),
                        liveness_probe: Some(Probe {
                            http_get: Some(HTTPGetAction {
                                path: Some("/health".to_string()),
                                port: IntOrString::Int(8080),
                                scheme: Some("HTTP".to_string()),
                                ..Default::default()
                            }),
                            initial_delay_seconds: Some(60),
                            period_seconds: Some(10),
                            success_threshold: Some(1),
                            timeout_seconds: Some(5),
                            failure_threshold: Some(3),
                            ..Default::default()
                        }),
                        readiness_probe: Some(Probe {
                            http_get: Some(HTTPGetAction {
                                path: Some("/ready".to_string()),
                                port: IntOrString::Int(8181),
                                scheme: Some("HTTP".to_string()),
                                ..Default::default()
                            }),
                            initial_delay_seconds: Some(10),
                            period_seconds: Some(10),
                            success_threshold: Some(1),
                            timeout_seconds: Some(5),
                            failure_threshold: Some(3),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    volumes: Some(vec![Volume {
                        name: "config-volume".to_string(),
                        config_map: Some(ConfigMapVolumeSource {
                            name: COREDNS_CONFIGMAP_NAME.to_string(),
                            items: Some(vec![KeyToPath {
                                key: "Corefile".to_string(),
                                path: "Corefile".to_string(),
                                ..Default::default()
                            }]),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        status: None,
    }
}

/// Generate a merge-patch JSON value to update the Corefile in an existing `ConfigMap`
/// while preserving any unrelated keys, labels, and metadata.
#[must_use]
pub fn generate_config_map_patch(corefile: &str) -> serde_json::Value {
    serde_json::json!({
        "data": {
            "Corefile": corefile
        }
    })
}

/// Returns true if an existing Service differs from the desired Service in its immutable
/// `cluster_ip` field, necessitating a deletion and recreation of the Service.
#[must_use]
pub fn should_recreate_service(existing: &Service, desired: &Service) -> bool {
    let Some(existing_spec) = &existing.spec else {
        return true;
    };
    let Some(desired_spec) = &desired.spec else {
        return false;
    };
    existing_spec.cluster_ip != desired_spec.cluster_ip
}
