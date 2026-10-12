use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, EnvVar, EnvVarSource, Namespace,
    ObjectFieldSelector, PodSpec, PodTemplateSpec, ResourceRequirements, ServiceAccount, Volume,
    VolumeMount,
};
use k8s_openapi::api::rbac::v1::{
    ClusterRole, ClusterRoleBinding, PolicyRule, Role, RoleBinding, RoleRef, Subject,
};
use k8s_openapi::api::storage::v1::StorageClass;
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use serde::Serialize;

use crate::config::{
    DEFAULT_APP_LABEL_KEY, DEFAULT_APP_LABEL_VALUE, DEFAULT_CONFIG_FILE_PATH,
    DEFAULT_CONFIG_MOUNT_PATH, DEFAULT_CPU_REQUEST, DEFAULT_MEMORY_LIMIT, DEFAULT_MEMORY_REQUEST,
    DEFAULT_NODE_PATH_KEY, DEFAULT_SETUP_SCRIPT, DEFAULT_TEARDOWN_SCRIPT,
    LOCAL_PATH_CLUSTER_ROLE_BINDING_NAME, LOCAL_PATH_CLUSTER_ROLE_NAME, LOCAL_PATH_CONFIGMAP_NAME,
    LOCAL_PATH_DEPLOYMENT_NAME, LOCAL_PATH_NAMESPACE, LOCAL_PATH_PROVISIONER_NAME,
    LOCAL_PATH_ROLE_BINDING_NAME, LOCAL_PATH_ROLE_NAME, LOCAL_PATH_SERVICE_ACCOUNT_NAME,
    LOCAL_PATH_STORAGE_CLASS_NAME, LocalPathConfig,
};
use crate::error::StorageError;

/// Full set of Kubernetes resources required for `local-path-provisioner`.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalPathManifests {
    pub namespace: Namespace,
    pub service_account: ServiceAccount,
    pub role: Role,
    pub cluster_role: ClusterRole,
    pub role_binding: RoleBinding,
    pub cluster_role_binding: ClusterRoleBinding,
    pub config_map: ConfigMap,
    pub deployment: Deployment,
    pub storage_class: StorageClass,
}

impl LocalPathManifests {
    /// Generate all manifests based on the provided `LocalPathConfig`.
    pub fn new(config: &LocalPathConfig) -> Result<Self, StorageError> {
        if !config.enabled {
            return Err(StorageError::InvalidConfiguration(
                "local-path storage is disabled in configuration".to_string(),
            ));
        }

        if config.reclaim_policy != "Retain" && config.reclaim_policy != "Delete" {
            return Err(StorageError::InvalidConfiguration(format!(
                "unsupported reclaim policy '{}': must be Retain or Delete",
                config.reclaim_policy
            )));
        }

        if config.volume_binding_mode != "WaitForFirstConsumer"
            && config.volume_binding_mode != "Immediate"
        {
            return Err(StorageError::InvalidConfiguration(format!(
                "unsupported volume binding mode '{}': must be WaitForFirstConsumer or Immediate",
                config.volume_binding_mode
            )));
        }

        let namespace = LOCAL_PATH_NAMESPACE;
        Ok(Self {
            namespace: generate_namespace(namespace),
            service_account: generate_service_account(LOCAL_PATH_SERVICE_ACCOUNT_NAME, namespace),
            role: generate_role(LOCAL_PATH_ROLE_NAME, namespace),
            cluster_role: generate_cluster_role(LOCAL_PATH_CLUSTER_ROLE_NAME),
            role_binding: generate_role_binding(
                LOCAL_PATH_ROLE_BINDING_NAME,
                namespace,
                LOCAL_PATH_ROLE_NAME,
                LOCAL_PATH_SERVICE_ACCOUNT_NAME,
            ),
            cluster_role_binding: generate_cluster_role_binding(
                LOCAL_PATH_CLUSTER_ROLE_BINDING_NAME,
                LOCAL_PATH_CLUSTER_ROLE_NAME,
                LOCAL_PATH_SERVICE_ACCOUNT_NAME,
                namespace,
            ),
            config_map: generate_config_map(config, namespace)?,
            deployment: generate_deployment(config, namespace),
            storage_class: generate_storage_class(config),
        })
    }
}

/// Standard labels for `local-path-provisioner`.
#[must_use]
pub fn provisioner_labels() -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(
        DEFAULT_APP_LABEL_KEY.to_string(),
        DEFAULT_APP_LABEL_VALUE.to_string(),
    );
    labels
}

/// Generate the dedicated `Namespace` for local-path storage.
#[must_use]
pub fn generate_namespace(namespace: &str) -> Namespace {
    Namespace {
        metadata: ObjectMeta {
            name: Some(namespace.to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Generate the `ServiceAccount` for local-path provisioner.
#[must_use]
pub fn generate_service_account(name: &str, namespace: &str) -> ServiceAccount {
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Generate namespaced `Role` permitting pod management.
#[must_use]
pub fn generate_role(name: &str, namespace: &str) -> Role {
    Role {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        rules: Some(vec![PolicyRule {
            api_groups: Some(vec![String::new()]),
            resources: Some(vec!["pods".to_string()]),
            verbs: vec![
                "get".to_string(),
                "list".to_string(),
                "watch".to_string(),
                "create".to_string(),
                "patch".to_string(),
                "update".to_string(),
                "delete".to_string(),
            ],
            ..Default::default()
        }]),
    }
}

/// Generate `ClusterRole` with volume, node, and storage class permissions.
#[must_use]
pub fn generate_cluster_role(name: &str) -> ClusterRole {
    ClusterRole {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec![
                    "nodes".to_string(),
                    "persistentvolumeclaims".to_string(),
                    "configmaps".to_string(),
                    "pods".to_string(),
                    "pods/log".to_string(),
                ]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["persistentvolumes".to_string()]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "create".to_string(),
                    "patch".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["events".to_string()]),
                verbs: vec!["create".to_string(), "patch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["storage.k8s.io".to_string()]),
                resources: Some(vec!["storageclasses".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
        ]),
        ..Default::default()
    }
}

/// Generate namespaced `RoleBinding` for the provisioner `ServiceAccount`.
#[must_use]
pub fn generate_role_binding(
    name: &str,
    namespace: &str,
    role_name: &str,
    service_account_name: &str,
) -> RoleBinding {
    RoleBinding {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "Role".to_string(),
            name: role_name.to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: service_account_name.to_string(),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        }]),
    }
}

/// Generate `ClusterRoleBinding` binding provisioner `ClusterRole` to its `ServiceAccount`.
#[must_use]
pub fn generate_cluster_role_binding(
    name: &str,
    cluster_role_name: &str,
    service_account_name: &str,
    service_account_namespace: &str,
) -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: cluster_role_name.to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: service_account_name.to_string(),
            namespace: Some(service_account_namespace.to_string()),
            ..Default::default()
        }]),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NodePathMapEntry<'a> {
    node: &'a str,
    paths: Vec<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SharedFileSystemConfig<'a> {
    shared_file_system_path: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalFileSystemConfig<'a> {
    node_path_map: Vec<NodePathMapEntry<'a>>,
}

/// Format the `config.json` payload matching Go upstream indentation exactly.
pub fn generate_config_json(config: &LocalPathConfig) -> Result<String, StorageError> {
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut buf, formatter);

    if let Some(ref shared) = config.shared_path {
        let payload = SharedFileSystemConfig {
            shared_file_system_path: shared.as_str(),
        };
        payload.serialize(&mut serializer)?;
    } else {
        let payload = LocalFileSystemConfig {
            node_path_map: vec![NodePathMapEntry {
                node: DEFAULT_NODE_PATH_KEY,
                paths: vec![config.storage_path.as_str()],
            }],
        };
        payload.serialize(&mut serializer)?;
    }

    String::from_utf8(buf).map_err(|e| StorageError::Manifest(e.to_string()))
}

/// Format helper pod YAML specification.
#[must_use]
pub fn generate_helper_pod_yaml(helper_image: &str) -> String {
    format!(
        "apiVersion: v1\n\
kind: Pod\n\
metadata:\n  \
  name: helper-pod\n\
spec:\n  \
  priorityClassName: system-node-critical\n  \
  tolerations:\n    \
    - key: node.kubernetes.io/disk-pressure\n      \
      operator: Exists\n      \
      effect: NoSchedule\n  \
  containers:\n  \
  - name: helper-pod\n    \
    image: {helper_image}\n    \
    imagePullPolicy: IfNotPresent"
    )
}

/// Generate `ConfigMap` containing `config.json`, helper scripts, and `helperPod.yaml`.
pub fn generate_config_map(
    config: &LocalPathConfig,
    namespace: &str,
) -> Result<ConfigMap, StorageError> {
    let config_json = generate_config_json(config)?;
    let helper_pod = generate_helper_pod_yaml(&config.helper_image);

    let mut data = BTreeMap::new();
    data.insert("config.json".to_string(), config_json);
    data.insert("setup".to_string(), DEFAULT_SETUP_SCRIPT.to_string());
    data.insert("teardown".to_string(), DEFAULT_TEARDOWN_SCRIPT.to_string());
    data.insert("helperPod.yaml".to_string(), helper_pod);

    Ok(ConfigMap {
        metadata: ObjectMeta {
            name: Some(LOCAL_PATH_CONFIGMAP_NAME.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    })
}

/// Generate default `StorageClass` for local-path storage.
#[must_use]
pub fn generate_storage_class(config: &LocalPathConfig) -> StorageClass {
    let mut annotations = BTreeMap::new();
    if config.default_class {
        annotations.insert(
            "storageclass.kubernetes.io/is-default-class".to_string(),
            "true".to_string(),
        );
    }

    StorageClass {
        metadata: ObjectMeta {
            name: Some(LOCAL_PATH_STORAGE_CLASS_NAME.to_string()),
            annotations: if annotations.is_empty() {
                None
            } else {
                Some(annotations)
            },
            ..Default::default()
        },
        provisioner: LOCAL_PATH_PROVISIONER_NAME.to_string(),
        volume_binding_mode: Some(config.volume_binding_mode.clone()),
        reclaim_policy: Some(config.reclaim_policy.clone()),
        ..Default::default()
    }
}

/// Generate `Deployment` for local-path provisioner.
#[must_use]
pub fn generate_deployment(config: &LocalPathConfig, namespace: &str) -> Deployment {
    let labels = provisioner_labels();

    let mut limits = BTreeMap::new();
    limits.insert(
        "memory".to_string(),
        Quantity(DEFAULT_MEMORY_LIMIT.to_string()),
    );

    let mut requests = BTreeMap::new();
    requests.insert("cpu".to_string(), Quantity(DEFAULT_CPU_REQUEST.to_string()));
    requests.insert(
        "memory".to_string(),
        Quantity(DEFAULT_MEMORY_REQUEST.to_string()),
    );

    let container = Container {
        name: LOCAL_PATH_DEPLOYMENT_NAME.to_string(),
        image: Some(config.provisioner_image.clone()),
        image_pull_policy: Some("IfNotPresent".to_string()),
        command: Some(vec![
            "local-path-provisioner".to_string(),
            "start".to_string(),
            "--config".to_string(),
            DEFAULT_CONFIG_FILE_PATH.to_string(),
        ]),
        env: Some(vec![
            EnvVar {
                name: "POD_NAMESPACE".to_string(),
                value_from: Some(EnvVarSource {
                    field_ref: Some(ObjectFieldSelector {
                        field_path: "metadata.namespace".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            EnvVar {
                name: "CONFIG_MOUNT_PATH".to_string(),
                value: Some(DEFAULT_CONFIG_MOUNT_PATH.to_string()),
                ..Default::default()
            },
        ]),
        resources: Some(ResourceRequirements {
            limits: Some(limits),
            requests: Some(requests),
            ..Default::default()
        }),
        volume_mounts: Some(vec![VolumeMount {
            name: "config-volume".to_string(),
            mount_path: DEFAULT_CONFIG_MOUNT_PATH.to_string(),
            ..Default::default()
        }]),
        ..Default::default()
    };

    let volume = Volume {
        name: "config-volume".to_string(),
        config_map: Some(ConfigMapVolumeSource {
            name: LOCAL_PATH_CONFIGMAP_NAME.to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };

    Deployment {
        metadata: ObjectMeta {
            name: Some(LOCAL_PATH_DEPLOYMENT_NAME.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some(LOCAL_PATH_SERVICE_ACCOUNT_NAME.to_string()),
                    containers: vec![container],
                    volumes: Some(vec![volume]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Generate a merge-patch JSON value to update configuration and helper scripts
/// in an existing `ConfigMap` while preserving any unrelated keys, labels, and metadata.
#[must_use]
pub fn generate_config_map_patch(config_map: &ConfigMap) -> serde_json::Value {
    serde_json::json!({
        "data": config_map.data
    })
}
