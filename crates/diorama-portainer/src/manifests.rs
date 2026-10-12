use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy};
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapEnvSource, ConfigMapKeySelector, Container, ContainerPort, EnvFromSource,
    EnvVar, EnvVarSource, Namespace, ObjectFieldSelector, PodSpec, PodTemplateSpec,
    ResourceRequirements, Secret, SecretKeySelector, Service, ServiceAccount, ServicePort,
    ServiceSpec,
};
use k8s_openapi::api::rbac::v1::{ClusterRoleBinding, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use serde::Serialize;

use crate::config::{
    CLUSTER_ADMIN_CLUSTER_ROLE_NAME, PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME,
    PORTAINER_AGENT_CONFIGMAP_NAME, PORTAINER_AGENT_DEPLOYMENT_NAME, PORTAINER_AGENT_PORT_EDGE,
    PORTAINER_AGENT_PORT_HTTP, PORTAINER_AGENT_SECRET_NAME, PORTAINER_AGENT_SERVICE_ACCOUNT_NAME,
    PORTAINER_AGENT_SERVICE_NAME, PORTAINER_NAMESPACE, PortainerAgentConfig,
};
use crate::error::PortainerError;

/// Full set of Kubernetes manifests for bootstrapping the Portainer Edge Agent.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PortainerManifests {
    /// Dedicated namespace for Portainer components (`portainer`).
    pub namespace: Namespace,
    /// `ServiceAccount` used by the agent pod (`portainer-sa-clusteradmin`).
    pub service_account: ServiceAccount,
    /// `ClusterRoleBinding` binding the `ServiceAccount` to `cluster-admin`.
    pub cluster_role_binding: ClusterRoleBinding,
    /// `ConfigMap` holding Edge agent environment variables (`portainer-agent-edge`).
    pub config_map: ConfigMap,
    /// Secret holding the Portainer Edge key (`portainer-agent-edge-key`).
    pub secret: Secret,
    /// Headless Service for Portainer agent pod addressing (`portainer-agent`).
    pub service: Service,
    /// Deployment running the Portainer Edge agent pod (`portainer-agent`).
    pub deployment: Deployment,
}

impl PortainerManifests {
    /// Generate all manifests from the given `PortainerAgentConfig`.
    ///
    /// Validates credentials and platform architecture:
    /// - Rejects unsupported architectures (e.g. RISC-V 64).
    /// - Rejects missing credentials (both edge ID and edge key empty).
    /// - Rejects partial/incomplete credentials.
    /// - Rejects empty image reference.
    pub fn new(config: &PortainerAgentConfig) -> Result<Self, PortainerError> {
        if !config.is_architecture_supported() {
            return Err(PortainerError::UnsupportedArchitecture(config.architecture));
        }

        if config.has_missing_credentials() {
            return Err(PortainerError::MissingCredentials);
        }

        if config.has_partial_credentials() {
            return Err(PortainerError::IncompleteCredentials {
                has_id: !config.edge_id.is_empty(),
                has_key: !config.edge_key.is_empty(),
            });
        }

        if config.image.is_empty() {
            return Err(PortainerError::InvalidImage(
                "image reference cannot be empty".to_string(),
            ));
        }

        let namespace = generate_namespace();
        let service_account = generate_service_account();
        let cluster_role_binding = generate_cluster_role_binding();
        let config_map = generate_config_map(config);
        let secret = generate_secret(&config.edge_key);
        let service = generate_service();
        let deployment = generate_deployment(config);

        Ok(Self {
            namespace,
            service_account,
            cluster_role_binding,
            config_map,
            secret,
            service,
            deployment,
        })
    }

    /// Convert manifests into a list of generic JSON values with kind and metadata preserved.
    pub fn to_json_values(&self) -> Result<Vec<serde_json::Value>, PortainerError> {
        let ns = serde_json::to_value(&self.namespace)
            .map_err(|e| PortainerError::Serialization(e.to_string()))?;
        let sa = serde_json::to_value(&self.service_account)
            .map_err(|e| PortainerError::Serialization(e.to_string()))?;
        let crb = serde_json::to_value(&self.cluster_role_binding)
            .map_err(|e| PortainerError::Serialization(e.to_string()))?;
        let cm = serde_json::to_value(&self.config_map)
            .map_err(|e| PortainerError::Serialization(e.to_string()))?;
        let secret = serde_json::to_value(&self.secret)
            .map_err(|e| PortainerError::Serialization(e.to_string()))?;
        let svc = serde_json::to_value(&self.service)
            .map_err(|e| PortainerError::Serialization(e.to_string()))?;
        let deploy = serde_json::to_value(&self.deployment)
            .map_err(|e| PortainerError::Serialization(e.to_string()))?;

        Ok(vec![ns, sa, crb, cm, secret, svc, deploy])
    }
}

/// Generates the `portainer` Namespace resource.
fn generate_namespace() -> Namespace {
    Namespace {
        metadata: ObjectMeta {
            name: Some(PORTAINER_NAMESPACE.to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Generates the `portainer-sa-clusteradmin` `ServiceAccount` resource.
fn generate_service_account() -> ServiceAccount {
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some(PORTAINER_AGENT_SERVICE_ACCOUNT_NAME.to_string()),
            namespace: Some(PORTAINER_NAMESPACE.to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Generates the `portainer-crb-clusteradmin` `ClusterRoleBinding` resource.
fn generate_cluster_role_binding() -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME.to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: CLUSTER_ADMIN_CLUSTER_ROLE_NAME.to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: PORTAINER_AGENT_SERVICE_ACCOUNT_NAME.to_string(),
            namespace: Some(PORTAINER_NAMESPACE.to_string()),
            ..Default::default()
        }]),
    }
}

/// Generates the `portainer-agent-edge` `ConfigMap` resource.
fn generate_config_map(config: &PortainerAgentConfig) -> ConfigMap {
    let mut data = BTreeMap::new();
    data.insert("EDGE_ID".to_string(), config.edge_id.clone());
    data.insert(
        "EDGE_INSECURE_POLL".to_string(),
        config.edge_insecure_poll.clone(),
    );
    data.insert(
        "EDGE_ASYNC".to_string(),
        if config.edge_async {
            "true".to_string()
        } else {
            "false".to_string()
        },
    );

    if let Some(secret) = &config.edge_secret
        && !secret.is_empty()
    {
        data.insert("EDGE_SECRET".to_string(), secret.clone());
    }

    for (k, v) in &config.env_vars {
        data.insert(k.clone(), v.clone());
    }

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(PORTAINER_AGENT_CONFIGMAP_NAME.to_string()),
            namespace: Some(PORTAINER_NAMESPACE.to_string()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

/// Generates the `portainer-agent-edge-key` Secret resource.
fn generate_secret(edge_key: &str) -> Secret {
    let mut string_data = BTreeMap::new();
    string_data.insert("edge.key".to_string(), edge_key.to_string());

    Secret {
        metadata: ObjectMeta {
            name: Some(PORTAINER_AGENT_SECRET_NAME.to_string()),
            namespace: Some(PORTAINER_NAMESPACE.to_string()),
            ..Default::default()
        },
        type_: Some("Opaque".to_string()),
        string_data: Some(string_data),
        ..Default::default()
    }
}

/// Generates the `portainer-agent` headless Service resource.
fn generate_service() -> Service {
    let mut selector = BTreeMap::new();
    selector.insert(
        "app".to_string(),
        PORTAINER_AGENT_DEPLOYMENT_NAME.to_string(),
    );

    let ports = vec![
        ServicePort {
            name: Some("edge".to_string()),
            port: PORTAINER_AGENT_PORT_EDGE,
            protocol: Some("TCP".to_string()),
            target_port: Some(IntOrString::Int(0)),
            ..Default::default()
        },
        ServicePort {
            name: Some("http".to_string()),
            port: PORTAINER_AGENT_PORT_HTTP,
            protocol: Some("TCP".to_string()),
            target_port: Some(IntOrString::Int(0)),
            ..Default::default()
        },
    ];

    Service {
        metadata: ObjectMeta {
            name: Some(PORTAINER_AGENT_SERVICE_NAME.to_string()),
            namespace: Some(PORTAINER_NAMESPACE.to_string()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_string()),
            publish_not_ready_addresses: Some(true),
            selector: Some(selector),
            ports: Some(ports),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Generates the environment variables for the Portainer Edge Agent container.
fn generate_agent_env(config: &PortainerAgentConfig) -> Vec<EnvVar> {
    let mut env = vec![
        EnvVar {
            name: "LOG_LEVEL".to_string(),
            value: Some("INFO".to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "EDGE".to_string(),
            value: Some("1".to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "AGENT_CLUSTER_ADDR".to_string(),
            value: Some(PORTAINER_AGENT_SERVICE_NAME.to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "KUBERNETES_POD_IP".to_string(),
            value_from: Some(EnvVarSource {
                field_ref: Some(ObjectFieldSelector {
                    field_path: "status.podIP".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
        EnvVar {
            name: "EDGE_KEY".to_string(),
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    name: PORTAINER_AGENT_SECRET_NAME.to_string(),
                    key: "edge.key".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
    ];

    if let Some(secret) = &config.edge_secret
        && !secret.is_empty()
    {
        env.push(EnvVar {
            name: "AGENT_SECRET".to_string(),
            value_from: Some(EnvVarSource {
                config_map_key_ref: Some(ConfigMapKeySelector {
                    name: PORTAINER_AGENT_CONFIGMAP_NAME.to_string(),
                    key: "EDGE_SECRET".to_string(),
                    optional: Some(true),
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
    }

    env
}

/// Generates the container specification for the Portainer Edge Agent.
fn generate_agent_container(config: &PortainerAgentConfig) -> Container {
    let ports = vec![
        ContainerPort {
            container_port: PORTAINER_AGENT_PORT_EDGE,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        },
        ContainerPort {
            container_port: PORTAINER_AGENT_PORT_HTTP,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        },
    ];

    let env_from = vec![EnvFromSource {
        config_map_ref: Some(ConfigMapEnvSource {
            name: PORTAINER_AGENT_CONFIGMAP_NAME.to_string(),
            ..Default::default()
        }),
        ..Default::default()
    }];

    Container {
        name: "portainer-agent".to_string(),
        image: Some(config.image.clone()),
        image_pull_policy: Some("IfNotPresent".to_string()),
        ports: Some(ports),
        env_from: Some(env_from),
        env: Some(generate_agent_env(config)),
        resources: Some(ResourceRequirements::default()),
        ..Default::default()
    }
}

/// Generates the `portainer-agent` Deployment resource.
fn generate_deployment(config: &PortainerAgentConfig) -> Deployment {
    let mut match_labels = BTreeMap::new();
    match_labels.insert(
        "app".to_string(),
        PORTAINER_AGENT_DEPLOYMENT_NAME.to_string(),
    );

    let mut pod_labels = BTreeMap::new();
    pod_labels.insert(
        "app".to_string(),
        PORTAINER_AGENT_DEPLOYMENT_NAME.to_string(),
    );

    Deployment {
        metadata: ObjectMeta {
            name: Some(PORTAINER_AGENT_DEPLOYMENT_NAME.to_string()),
            namespace: Some(PORTAINER_NAMESPACE.to_string()),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(match_labels),
                ..Default::default()
            },
            strategy: Some(DeploymentStrategy::default()),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(pod_labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some(PORTAINER_AGENT_SERVICE_ACCOUNT_NAME.to_string()),
                    containers: vec![generate_agent_container(config)],
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}
