#![forbid(unsafe_code)]

//! Kubernetes local-path storage provisioner resources and configuration for diorama.
//!
//! Provides types, manifest generators, and configuration models for deploying
//! the `rancher.io/local-path` persistent storage provisioner, including RBAC,
//! `ConfigMap` resources, helper scripts, `Deployment`, default `StorageClass`,
//! idempotent reconciliation, and supervisor integration.

pub mod config;
pub mod error;
pub mod health;
pub mod manifests;
pub mod reconciler;
pub mod service;
pub mod supervisor;
pub mod volume;

pub use config::{
    DEFAULT_ALLOW_VOLUME_EXPANSION, DEFAULT_APP_LABEL_KEY, DEFAULT_APP_LABEL_VALUE,
    DEFAULT_BASE_STORAGE_PATH, DEFAULT_CONFIG_FILE_PATH, DEFAULT_CONFIG_MOUNT_PATH,
    DEFAULT_CPU_REQUEST, DEFAULT_HELPER_IMAGE, DEFAULT_MEMORY_LIMIT, DEFAULT_MEMORY_REQUEST,
    DEFAULT_NODE_PATH_KEY, DEFAULT_PROVISIONER_IMAGE, DEFAULT_READINESS_TIMEOUT,
    DEFAULT_RECLAIM_POLICY, DEFAULT_SETUP_SCRIPT, DEFAULT_STORAGE_DIR_NAME,
    DEFAULT_TEARDOWN_SCRIPT, DEFAULT_VOLUME_BINDING_MODE, IS_DEFAULT_CLASS_ANNOTATION,
    LOCAL_PATH_CLUSTER_ROLE_BINDING_NAME, LOCAL_PATH_CLUSTER_ROLE_NAME, LOCAL_PATH_CONFIGMAP_NAME,
    LOCAL_PATH_DEPLOYMENT_NAME, LOCAL_PATH_NAMESPACE, LOCAL_PATH_PROVISIONER_NAME,
    LOCAL_PATH_ROLE_BINDING_NAME, LOCAL_PATH_ROLE_NAME, LOCAL_PATH_SERVICE_ACCOUNT_NAME,
    LOCAL_PATH_STORAGE_CLASS_NAME, LocalPathConfig, PV_PROTECTION_FINALIZER,
    PVC_PROTECTION_FINALIZER, STORAGE_PROVISIONED_BY_ANNOTATION, VOLUME_SELECTED_NODE_ANNOTATION,
};
pub use error::{Result, StorageError};
pub use health::LocalPathHealthReport;
pub use manifests::{
    LocalPathManifests, generate_cluster_role, generate_cluster_role_binding, generate_config_json,
    generate_config_map, generate_config_map_patch, generate_csi_driver, generate_csi_node,
    generate_csi_storage_capacity, generate_deployment, generate_helper_pod_yaml,
    generate_namespace, generate_role, generate_role_binding, generate_service_account,
    generate_storage_class, generate_volume_attachment, generate_volume_attributes_class,
    provisioner_labels,
};
pub use reconciler::{LocalPathReconciler, ReconciliationReport};
pub use service::LocalPathService;
pub use supervisor::{COMPONENT_LOCAL_PATH, DEFAULT_STARTUP_TIMEOUT, LocalPathAdapter};
pub use volume::{
    LocalPathVolumeManager, VolumeReclaimAction, safe_resolve_volume_path, safe_teardown_volume_dir,
};
