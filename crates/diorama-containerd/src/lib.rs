//! Managed containerd runtime integration for diorama Kube.
//!
//! Provides generation of containerd v3 configuration, runtime and CRI
//! endpoint settings, shim lookup via PATH resolution, snapshotter selection,
//! registry `hosts.toml` configuration, and immutable symlink handling.

pub mod cgroup;
pub mod cleanup;
pub mod client;
pub mod config;
pub mod health;
pub mod image;
pub mod namespace;
pub mod registry;
pub mod service;
pub mod shim;
pub mod snapshotter;
pub mod symlink;

pub use cgroup::{evaluate_systemd_cgroup, is_cgroup_v2, is_systemd_running, use_systemd_cgroup};
pub use cleanup::{
    CleanupError, CleanupReport, clean_stale_runtime_state, reclaim_managed_runtime,
    validate_cleanup_path,
};
pub use client::connect_unix;
pub use config::{
    CONTAINERD_CONFIG_VERSION, ContainerdConfigFile, ContainerdConfigOptions,
    ContainerdServicePaths, DEFAULT_CONTAINERD_CONFIG_DIR, DEFAULT_RUNTIME_NAME,
    DEFAULT_SANDBOX_IMAGE, DEFAULT_STANDARD_CNI_CONF_DIR, generate_containerd_config,
    render_containerd_config, write_containerd_config_file,
};
pub use health::{
    DEFAULT_READINESS_TIMEOUT, DEFAULT_RETRY_INTERVAL, HealthError, RuntimeVersionInfo,
    check_containerd_version, check_cri_version, probe_containerd_readiness,
};
pub use image::{
    DEFAULT_BUSYBOX_IMAGE, DEFAULT_COREDNS_IMAGE, DEFAULT_D2K_IMAGE, DEFAULT_LOCAL_PATH_IMAGE,
    DEFAULT_PAUSE_IMAGE, DEFAULT_PORTAINER_AGENT_IMAGE, ImageError, ImageImportConfig,
    ImageImportSummary, ImageTarget, import_or_pull_images,
};
pub use namespace::{DEFAULT_K8S_NAMESPACE, NamespaceError, ensure_k8s_namespace, with_namespace};
pub use registry::{
    HostEndpointConfig, RegistryError, RegistryHostFile, ensure_registry_dir,
    list_configured_registries, read_registry_hosts_toml, write_registry_hosts_toml,
};
pub use service::{
    COMPONENT_CONTAINERD, ContainerdPaths, ContainerdService, ContainerdServiceOptions,
    clear_prepare_failure, last_prepare_failure,
};
pub use shim::{
    DEFAULT_SHIM_BINARY_NAME, RUNTIME_RUNC_V2, ShimError, build_containerd_path, find_shim_in_path,
    validate_runtime_spec,
};
pub use snapshotter::{
    OVERLAYFS_SUPER_MAGIC, Snapshotter, check_fuse_overlayfs_in_path, detect_snapshotter,
    is_overlayfs, select_snapshotter,
};
pub use symlink::{
    DEFAULT_SYSTEM_CONTAINERD_SOCK, SymlinkError, ensure_symbolic_link, ensure_system_socket_link,
};
