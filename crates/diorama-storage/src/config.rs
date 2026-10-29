use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default timeout for deployment readiness polling.
pub const DEFAULT_READINESS_TIMEOUT: Duration = Duration::from_mins(1);

const fn default_readiness_timeout() -> Duration {
    DEFAULT_READINESS_TIMEOUT
}

/// Namespace where `local-path-provisioner` and its RBAC/ConfigMap/Deployment run.
pub const LOCAL_PATH_NAMESPACE: &str = "local-path-storage";

/// Name of the `ServiceAccount` used by `local-path-provisioner`.
pub const LOCAL_PATH_SERVICE_ACCOUNT_NAME: &str = "local-path-provisioner-service-account";

/// Name of the `Role` and `ClusterRole` for `local-path-provisioner`.
pub const LOCAL_PATH_ROLE_NAME: &str = "local-path-provisioner-role";
pub const LOCAL_PATH_CLUSTER_ROLE_NAME: &str = "local-path-provisioner-role";

/// Name of the `RoleBinding` and `ClusterRoleBinding` for `local-path-provisioner`.
pub const LOCAL_PATH_ROLE_BINDING_NAME: &str = "local-path-provisioner-bind";
pub const LOCAL_PATH_CLUSTER_ROLE_BINDING_NAME: &str = "local-path-provisioner-bind";

/// Name of the `ConfigMap` storing provisioner configuration and helper scripts.
pub const LOCAL_PATH_CONFIGMAP_NAME: &str = "local-path-config";

/// Name of the `Deployment` managing `local-path-provisioner`.
pub const LOCAL_PATH_DEPLOYMENT_NAME: &str = "local-path-provisioner";

/// Name of the default `StorageClass` created by `local-path-provisioner`.
pub const LOCAL_PATH_STORAGE_CLASS_NAME: &str = "local-path";

/// Standard provisioner identifier registered with Kubernetes.
pub const LOCAL_PATH_PROVISIONER_NAME: &str = "rancher.io/local-path";

/// Default pinned image reference for `local-path-provisioner`.
pub const DEFAULT_PROVISIONER_IMAGE: &str = "docker.io/rancher/local-path-provisioner:v0.0.36";

/// Default helper pod container image.
pub const DEFAULT_HELPER_IMAGE: &str = "docker.io/library/busybox:latest";

/// Default directory name under cluster base path for host persistent storage.
pub const DEFAULT_STORAGE_DIR_NAME: &str = "local-path-storage";

/// Standard fallback host storage directory when no explicit base path is set.
pub const DEFAULT_BASE_STORAGE_PATH: &str = "/var/lib/diorama/local-path-storage";

/// Default whether the `StorageClass` allows volume expansion.
pub const DEFAULT_ALLOW_VOLUME_EXPANSION: bool = true;

const fn default_true() -> bool {
    true
}

/// Standard finalizer for PVC protection against deletion while in use.
pub const PVC_PROTECTION_FINALIZER: &str = "kubernetes.io/pvc-protection";

/// Standard finalizer for PV protection against deletion while bound or in use.
pub const PV_PROTECTION_FINALIZER: &str = "kubernetes.io/pv-protection";

/// Standard annotation set on PVC when a consumer Pod is scheduled to a node.
pub const VOLUME_SELECTED_NODE_ANNOTATION: &str = "volume.kubernetes.io/selected-node";

/// Standard annotation set on dynamically provisioned `PersistentVolumes`.
pub const STORAGE_PROVISIONED_BY_ANNOTATION: &str = "pv.kubernetes.io/provisioned-by";

/// Standard annotation for marking default `StorageClass`.
pub const IS_DEFAULT_CLASS_ANNOTATION: &str = "storageclass.kubernetes.io/is-default-class";

/// Default `PersistentVolume` reclaim policy for the `local-path` `StorageClass`.
pub const DEFAULT_RECLAIM_POLICY: &str = "Retain";

/// Default volume binding mode for the `local-path` `StorageClass`.
pub const DEFAULT_VOLUME_BINDING_MODE: &str = "WaitForFirstConsumer";

/// Mount path for provisioner configuration inside the container.
pub const DEFAULT_CONFIG_MOUNT_PATH: &str = "/etc/config/";

/// Configuration file path inside the provisioner container.
pub const DEFAULT_CONFIG_FILE_PATH: &str = "/etc/config/config.json";

/// Label key applied to `local-path-provisioner` objects.
pub const DEFAULT_APP_LABEL_KEY: &str = "app";

/// Label value applied to `local-path-provisioner` objects.
pub const DEFAULT_APP_LABEL_VALUE: &str = "local-path-provisioner";

/// Sentinel key representing non-listed nodes in `nodePathMap`.
pub const DEFAULT_NODE_PATH_KEY: &str = "DEFAULT_PATH_FOR_NON_LISTED_NODES";

/// Default memory limit for the provisioner container (avoids historical OOM errors).
pub const DEFAULT_MEMORY_LIMIT: &str = "128Mi";

/// Default memory request for the provisioner container.
pub const DEFAULT_MEMORY_REQUEST: &str = "32Mi";

/// Default CPU request for the provisioner container.
pub const DEFAULT_CPU_REQUEST: &str = "50m";

/// Shell script placed in `setup` key of `local-path-config` `ConfigMap`.
pub const DEFAULT_SETUP_SCRIPT: &str = "#!/bin/sh\nset -eu\nmkdir -m 0777 -p \"$VOL_DIR\"";

/// Shell script placed in `teardown` key of `local-path-config` `ConfigMap`.
pub const DEFAULT_TEARDOWN_SCRIPT: &str = "#!/bin/sh\nset -eu\nrm -rf \"$VOL_DIR\"";

/// Storage configuration for local-path provisioner and `StorageClass` generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct LocalPathConfig {
    /// Whether local-path storage component is enabled (defaults to true per D04).
    pub enabled: bool,

    /// Host directory path for volume allocations when not using a shared filesystem.
    pub storage_path: String,

    /// Optional shared filesystem path overriding `nodePathMap`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_path: Option<String>,

    /// Container image for the `local-path-provisioner` deployment.
    pub provisioner_image: String,

    /// Container image for helper pods running setup and teardown commands.
    pub helper_image: String,

    /// Reclaim policy for the default `StorageClass` (defaults to `Retain`).
    pub reclaim_policy: String,

    /// Volume binding mode for the default `StorageClass` (defaults to `WaitForFirstConsumer`).
    pub volume_binding_mode: String,

    /// Whether to mark this class as the default `StorageClass`.
    pub default_class: bool,

    /// Whether volume expansion is allowed for this `StorageClass`.
    #[serde(default = "default_true")]
    pub allow_volume_expansion: bool,

    /// Legacy opt-in for CSI fixture resources. Local-path is not a CSI driver.
    #[serde(default)]
    pub csi_enabled: bool,

    /// Timeout for deployment readiness polling.
    #[serde(default = "default_readiness_timeout")]
    pub readiness_timeout: Duration,
}

impl Default for LocalPathConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            storage_path: DEFAULT_BASE_STORAGE_PATH.to_string(),
            shared_path: None,
            provisioner_image: DEFAULT_PROVISIONER_IMAGE.to_string(),
            helper_image: DEFAULT_HELPER_IMAGE.to_string(),
            reclaim_policy: DEFAULT_RECLAIM_POLICY.to_string(),
            volume_binding_mode: DEFAULT_VOLUME_BINDING_MODE.to_string(),
            default_class: true,
            allow_volume_expansion: DEFAULT_ALLOW_VOLUME_EXPANSION,
            csi_enabled: false,
            readiness_timeout: DEFAULT_READINESS_TIMEOUT,
        }
    }
}

impl LocalPathConfig {
    /// Create a new `LocalPathConfig` with standard defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set timeout for deployment readiness polling.
    #[must_use]
    pub fn with_readiness_timeout(mut self, timeout: Duration) -> Self {
        self.readiness_timeout = timeout;
        self
    }

    /// Set whether local-path storage is enabled.
    #[must_use]
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set host storage path.
    #[must_use]
    pub fn with_storage_path(mut self, path: impl Into<String>) -> Self {
        self.storage_path = path.into();
        self
    }

    /// Set or clear optional shared filesystem path.
    #[must_use]
    pub fn with_shared_path(mut self, path: Option<String>) -> Self {
        self.shared_path = match path {
            Some(p) if !p.trim().is_empty() => Some(p.trim().to_string()),
            _ => None,
        };
        self
    }

    /// Set provisioner container image.
    #[must_use]
    pub fn with_provisioner_image(mut self, image: impl Into<String>) -> Self {
        self.provisioner_image = image.into();
        self
    }

    /// Set helper pod container image.
    #[must_use]
    pub fn with_helper_image(mut self, image: impl Into<String>) -> Self {
        self.helper_image = image.into();
        self
    }

    /// Set `PersistentVolume` reclaim policy.
    #[must_use]
    pub fn with_reclaim_policy(mut self, policy: impl Into<String>) -> Self {
        self.reclaim_policy = policy.into();
        self
    }

    /// Set volume binding mode.
    #[must_use]
    pub fn with_volume_binding_mode(mut self, mode: impl Into<String>) -> Self {
        self.volume_binding_mode = mode.into();
        self
    }

    /// Set whether the `StorageClass` is default.
    #[must_use]
    pub fn with_default_class(mut self, default: bool) -> Self {
        self.default_class = default;
        self
    }

    /// Set whether volume expansion is allowed.
    #[must_use]
    pub fn with_allow_volume_expansion(mut self, allow: bool) -> Self {
        self.allow_volume_expansion = allow;
        self
    }

    /// Set whether CSI resources (`CSIDriver`, etc.) are reconciled.
    #[must_use]
    pub fn with_csi_enabled(mut self, enabled: bool) -> Self {
        self.csi_enabled = enabled;
        self
    }

    /// Construct `LocalPathConfig` from a cluster-wide `diorama_config::Config`.
    #[must_use]
    pub fn from_diorama_config(config: &diorama_config::Config) -> Self {
        let shared = if config.storage.local_path.shared_path.trim().is_empty() {
            None
        } else {
            Some(config.storage.local_path.shared_path.trim().to_string())
        };

        let storage_path = Path::new(&config.path)
            .join(DEFAULT_STORAGE_DIR_NAME)
            .display()
            .to_string();

        Self {
            enabled: config.storage.local_path.enabled,
            storage_path,
            shared_path: shared,
            provisioner_image: DEFAULT_PROVISIONER_IMAGE.to_string(),
            helper_image: DEFAULT_HELPER_IMAGE.to_string(),
            reclaim_policy: DEFAULT_RECLAIM_POLICY.to_string(),
            volume_binding_mode: DEFAULT_VOLUME_BINDING_MODE.to_string(),
            default_class: true,
            allow_volume_expansion: DEFAULT_ALLOW_VOLUME_EXPANSION,
            csi_enabled: false,
            readiness_timeout: DEFAULT_READINESS_TIMEOUT,
        }
    }
}
