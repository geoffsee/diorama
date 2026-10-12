//! Kubelet configuration, node registration, and single-node workload execution.
//!
//! Provides configuration generation matching official upstream `kubelet.config.k8s.io/v1beta1`,
//! node identity and RBAC integration, a CRI-shaped runtime contract with an in-memory mock and a
//! container-engine adapter, Node registration and lease heartbeats, and pod execution.

pub mod config;
pub mod container;
pub mod cri;
pub mod engine;
pub mod error;
pub mod health;
pub mod mock;
pub mod podman;
pub mod reconciler;
pub mod registration;
pub mod service;
pub mod status;
pub mod supervisor;
pub mod workload;

pub use config::{
    CPU_MANAGER_CHECKPOINT_FILE, CpuManagerSettings, DEFAULT_CLUSTER_DNS, DEFAULT_CLUSTER_DOMAIN,
    DEFAULT_HEALTHZ_BIND_ADDRESS, DEFAULT_HEALTHZ_PORT, DEFAULT_KUBELET_PORT,
    DEFAULT_KUBELET_READ_ONLY_PORT, DEFAULT_KUBELET_ROOT_DIR, KubeletConfigOptions,
    detect_host_cpu_count, format_cpuset, parse_cpuset, render_canonical_yaml,
};
pub use container::{
    CgroupSetupStatus, ContainerEnvironment, Ipv6DisableStatus, KubeletCgroupVersion,
    MountPropagationStatus,
};
pub use cri::{CriRuntimeProvider, parse_cri_logs, parse_rfc3339_unix_secs};
pub use engine::{
    ContainerEngine, ContainerSpec, ContainerState, ContainerSummary, EngineRuntimeAdapter,
    MountSpec, PodSummary, PortMappingSpec, ResourceSpec,
};
pub use error::KubeletError;
pub use health::KubeletHealthReport;
pub use mock::MockRuntimeProvider;
pub use reconciler::{
    PodReconciler, PullPolicy, StartFailure, container_config, container_config_with_root,
    sandbox_config,
};
pub use service::{KubeletLogSource, KubeletService};
pub use status::{
    ContainerView, CpuAssignment, PodViews, observed_conditions, observed_phase, pod_status,
};
pub use supervisor::{COMPONENT_KUBELET, DEFAULT_STARTUP_TIMEOUT, KubeletAdapter};
pub use workload::{
    CpuManager, CpuManagerState, ExecResult, LogOptions, PodQoSClass, ReconcileReport,
    RestartPolicy, RuntimeProvider, WorkloadRestartReport, determine_pod_qos,
    is_container_cpu_pinning_eligible, parse_cpu_quantity_milli, parse_memory_quantity_bytes,
};
