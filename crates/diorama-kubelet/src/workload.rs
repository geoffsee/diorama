//! Runtime contracts shared by the kubelet reconciler and its runtime providers.
//!
//! [`RuntimeProvider`] is the CRI v1 surface the kubelet uses, expressed with the
//! generated `diorama_cri::runtime::v1` types so a containerd provider is a thin
//! wrapper over `diorama_cri::CriClient` and the podman engine adapts to the same
//! contract. The module also carries the `QoS` and CPU-manager helpers and the
//! host-side volume staging used while preparing a pod.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use diorama_apiserver::ApiserverService;

pub use diorama_cri::runtime::v1 as cri;

use crate::config::{KubeletConfigOptions, detect_host_cpu_count, format_cpuset, parse_cpuset};
use crate::error::KubeletError;

/// Result of executing a command in a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Log read options forwarded from the pod log subresource.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogOptions {
    pub tail_lines: Option<usize>,
    pub timestamps: bool,
    pub since_seconds: Option<u64>,
    /// Read the previous attempt of the container instead of the current one.
    pub previous: bool,
    /// Stream logs as they arrive.
    pub follow: bool,
}

/// `spec.restartPolicy`; absent means `Always`, as in Kubernetes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    Always,
    OnFailure,
    Never,
}

impl RestartPolicy {
    #[must_use]
    pub fn of(pod: &Value) -> Self {
        match pod.pointer("/spec/restartPolicy").and_then(Value::as_str) {
            Some("Never") => Self::Never,
            Some("OnFailure") => Self::OnFailure,
            _ => Self::Always,
        }
    }

    /// Whether a container that exited with `exit_code` is restarted.
    #[must_use]
    pub fn restarts(self, exit_code: i32) -> bool {
        match self {
            Self::Always => true,
            Self::OnFailure => exit_code != 0,
            Self::Never => false,
        }
    }
}

/// Summary of one pass over every pod in the cluster.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub bound: usize,
    pub synced: usize,
    pub failed: usize,
    pub orphans_stopped: usize,
}

/// Standard kubelet labels on sandboxes and containers, as crictl expects them.
pub const LABEL_POD_NAME: &str = "io.kubernetes.pod.name";
pub const LABEL_POD_NAMESPACE: &str = "io.kubernetes.pod.namespace";
pub const LABEL_POD_UID: &str = "io.kubernetes.pod.uid";
pub const LABEL_CONTAINER_NAME: &str = "io.kubernetes.container.name";
/// Annotation carrying the container attempt number.
pub const ANNOTATION_RESTART_COUNT: &str = "io.kubernetes.container.restartCount";
/// Marks sandboxes and containers this kubelet created; other `io.kubernetes.*` users are left alone.
pub const LABEL_MANAGED_BY: &str = "io.diorama.managed-by";
pub const MANAGED_BY: &str = "dioramalet";

fn unsupported(operation: &str) -> KubeletError {
    KubeletError::ContainerOperationFailed {
        container: operation.to_string(),
        reason: format!("{operation} is not supported by this runtime"),
    }
}

/// The CRI v1 operations the kubelet drives a runtime with.
///
/// Required methods are the ones the reconciler calls; a provider that cannot
/// perform one must fail loudly at compile time rather than at run time. The
/// remaining `RuntimeService` and `ImageService` RPCs are present for shape and
/// default to an error until something needs them. Timestamps in the CRI
/// types are nanoseconds since the Unix epoch; timeouts are seconds.
#[async_trait]
pub trait RuntimeProvider: std::fmt::Debug + Send + Sync {
    /// Runtime name used as the `containerID` scheme, e.g. `containerd`, `podman`.
    fn provider_name(&self) -> &str;

    /// Version string reported in the node's `containerRuntimeVersion`.
    fn runtime_version(&self) -> String {
        "v1.35.7".to_string()
    }

    /// Whether this provider requires a live unix domain socket path to exist on the host filesystem.
    fn requires_socket(&self) -> bool {
        false
    }

    /// Whether this provider represents an external runtime whose containers survive Kubelet restart.
    fn is_external(&self) -> bool {
        false
    }

    /// Verifies the runtime answers before the node reports Ready.
    async fn check_available(&self) -> Result<(), KubeletError> {
        Ok(())
    }

    // --- RuntimeService: sandboxes ---

    /// Creates and starts a pod sandbox; returns its id.
    async fn run_pod_sandbox(&self, config: &cri::PodSandboxConfig)
    -> Result<String, KubeletError>;

    /// Stops the sandbox and every container in it.
    async fn stop_pod_sandbox(&self, pod_sandbox_id: &str) -> Result<(), KubeletError>;

    /// Removes a stopped sandbox and its containers.
    async fn remove_pod_sandbox(&self, pod_sandbox_id: &str) -> Result<(), KubeletError>;

    async fn list_pod_sandbox(
        &self,
        filter: Option<&cri::PodSandboxFilter>,
    ) -> Result<Vec<cri::PodSandbox>, KubeletError>;

    async fn pod_sandbox_status(
        &self,
        pod_sandbox_id: &str,
    ) -> Result<cri::PodSandboxStatus, KubeletError>;

    // --- RuntimeService: containers ---

    /// Creates a container inside a sandbox; returns its id. The container is not started.
    async fn create_container(
        &self,
        pod_sandbox_id: &str,
        config: &cri::ContainerConfig,
        sandbox_config: &cri::PodSandboxConfig,
    ) -> Result<String, KubeletError>;

    async fn start_container(&self, container_id: &str) -> Result<(), KubeletError>;

    /// Stops a container: TERM, then KILL once `timeout_secs` has elapsed.
    async fn stop_container(
        &self,
        container_id: &str,
        timeout_secs: i64,
    ) -> Result<(), KubeletError>;

    async fn remove_container(&self, container_id: &str) -> Result<(), KubeletError>;

    async fn list_containers(
        &self,
        filter: Option<&cri::ContainerFilter>,
    ) -> Result<Vec<cri::Container>, KubeletError>;

    async fn container_status(
        &self,
        container_id: &str,
    ) -> Result<cri::ContainerStatus, KubeletError>;

    /// Runs a command in a container and waits for it.
    async fn exec_sync(
        &self,
        container_id: &str,
        cmd: &[String],
        timeout_secs: i64,
    ) -> Result<ExecResult, KubeletError>;

    /// Captured stdout and stderr of a container, interleaved in time order.
    ///
    /// CRI has no log RPC: the kubelet reads the file at `ContainerStatus.log_path`.
    /// Engines that keep logs themselves answer here instead.
    async fn container_logs(
        &self,
        container_id: &str,
        options: &LogOptions,
    ) -> Result<String, KubeletError>;

    // --- ImageService ---

    /// Returns the image if the runtime has it.
    async fn image_status(
        &self,
        image: &cri::ImageSpec,
    ) -> Result<Option<cri::Image>, KubeletError>;

    /// Pulls an image; returns its reference (digest or id).
    async fn pull_image(
        &self,
        image: &cri::ImageSpec,
        sandbox_config: Option<&cri::PodSandboxConfig>,
    ) -> Result<String, KubeletError>;

    // --- RPCs the reconciler does not use yet ---

    async fn container_stats(
        &self,
        container_id: &str,
    ) -> Result<cri::ContainerStats, KubeletError> {
        let _ = container_id;
        Err(unsupported("ContainerStats"))
    }

    async fn list_container_stats(
        &self,
        filter: Option<&cri::ContainerStatsFilter>,
    ) -> Result<Vec<cri::ContainerStats>, KubeletError> {
        let _ = filter;
        Err(unsupported("ListContainerStats"))
    }

    async fn attach(
        &self,
        request: &cri::AttachRequest,
    ) -> Result<cri::AttachResponse, KubeletError> {
        let _ = request;
        Err(unsupported("Attach"))
    }

    async fn port_forward(
        &self,
        request: &cri::PortForwardRequest,
    ) -> Result<cri::PortForwardResponse, KubeletError> {
        let _ = request;
        Err(unsupported("PortForward"))
    }

    async fn update_container_resources(
        &self,
        container_id: &str,
        resources: &cri::ContainerResources,
    ) -> Result<(), KubeletError> {
        let _ = (container_id, resources);
        Err(unsupported("UpdateContainerResources"))
    }

    async fn reopen_container_log(&self, container_id: &str) -> Result<(), KubeletError> {
        let _ = container_id;
        Err(unsupported("ReopenContainerLog"))
    }

    async fn list_images(
        &self,
        filter: Option<&cri::ImageFilter>,
    ) -> Result<Vec<cri::Image>, KubeletError> {
        let _ = filter;
        Err(unsupported("ListImages"))
    }

    async fn remove_image(&self, image: &cri::ImageSpec) -> Result<(), KubeletError> {
        let _ = image;
        Err(unsupported("RemoveImage"))
    }

    async fn image_fs_info(&self) -> Result<Vec<cri::FilesystemUsage>, KubeletError> {
        Err(unsupported("ImageFsInfo"))
    }
}

/// Container attempt label set, as the kubelet writes it on every container.
#[must_use]
pub fn container_labels(
    namespace: &str,
    pod_name: &str,
    pod_uid: &str,
    container_name: &str,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_MANAGED_BY.to_string(), MANAGED_BY.to_string()),
        (LABEL_POD_NAME.to_string(), pod_name.to_string()),
        (LABEL_POD_NAMESPACE.to_string(), namespace.to_string()),
        (LABEL_POD_UID.to_string(), pod_uid.to_string()),
        (LABEL_CONTAINER_NAME.to_string(), container_name.to_string()),
    ])
}

/// Sandbox label set.
#[must_use]
pub fn sandbox_labels(namespace: &str, pod_name: &str, pod_uid: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_MANAGED_BY.to_string(), MANAGED_BY.to_string()),
        (LABEL_POD_NAME.to_string(), pod_name.to_string()),
        (LABEL_POD_NAMESPACE.to_string(), namespace.to_string()),
        (LABEL_POD_UID.to_string(), pod_uid.to_string()),
    ])
}

/// Nanoseconds since the epoch for a Unix second count, as CRI reports time.
#[must_use]
pub fn nanos_from_secs(secs: u64) -> i64 {
    i64::try_from(secs.saturating_mul(1_000_000_000)).unwrap_or(i64::MAX)
}

/// Unix seconds for a CRI nanosecond timestamp; zero and negatives mean unset.
#[must_use]
pub fn secs_from_nanos(nanos: i64) -> Option<u64> {
    (nanos > 0).then(|| u64::try_from(nanos / 1_000_000_000).unwrap_or(0))
}

/// Kubernetes Quality of Service (`QoS`) classes for pods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PodQoSClass {
    Guaranteed,
    Burstable,
    BestEffort,
}

/// Parses a CPU quantity string into millicores.
/// Supports integers ("1" -> 1000), millicores ("500m" -> 500), and decimals ("1.5" -> 1500).
#[must_use]
pub fn parse_cpu_quantity_milli(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_suffix('m') {
        rest.parse::<u64>().ok()
    } else if let Ok(val) = s.parse::<u64>() {
        val.checked_mul(1000)
    } else if let Ok(f) = s.parse::<f64>() {
        #[allow(clippy::cast_precision_loss)]
        let max_f64 = (u64::MAX / 1000) as f64;
        if f.is_sign_negative() || f.is_nan() || f.is_infinite() || f > max_f64 {
            None
        } else {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let val = (f * 1000.0).round() as u64;
            Some(val)
        }
    } else {
        None
    }
}

/// Parses a memory quantity string into bytes.
#[must_use]
pub fn parse_memory_quantity_bytes(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(bytes) = s.parse::<u64>() {
        return Some(bytes);
    }
    let (num_str, mult) = if let Some(r) = s.strip_suffix("Ki") {
        (r, 1024u64)
    } else if let Some(r) = s.strip_suffix("Mi") {
        (r, 1024u64.saturating_pow(2))
    } else if let Some(r) = s.strip_suffix("Gi") {
        (r, 1024u64.saturating_pow(3))
    } else if let Some(r) = s.strip_suffix("Ti") {
        (r, 1024u64.saturating_pow(4))
    } else if let Some(r) = s.strip_suffix('k') {
        (r, 1000u64)
    } else if let Some(r) = s.strip_suffix('M') {
        (r, 1_000_000u64)
    } else {
        let r = s.strip_suffix('G')?;
        (r, 1_000_000_000u64)
    };
    num_str.parse::<u64>().ok().map(|n| n.saturating_mul(mult))
}

/// Determines the `QoS` class of a pod based on its container resource requirements.
#[must_use]
pub fn determine_pod_qos(pod: &Value) -> PodQoSClass {
    let containers = pod
        .get("spec")
        .and_then(|s| s.get("containers"))
        .and_then(Value::as_array);

    let Some(containers) = containers else {
        return PodQoSClass::BestEffort;
    };

    if containers.is_empty() {
        return PodQoSClass::BestEffort;
    }

    let mut has_requests_or_limits = false;
    let mut all_guaranteed = true;

    for container in containers {
        let resources = container.get("resources");
        let requests = resources.and_then(|r| r.get("requests"));
        let limits = resources.and_then(|r| r.get("limits"));

        let cpu_req = requests.and_then(|r| r.get("cpu")).and_then(Value::as_str);
        let cpu_lim = limits.and_then(|l| l.get("cpu")).and_then(Value::as_str);
        let mem_req = requests
            .and_then(|r| r.get("memory"))
            .and_then(Value::as_str);
        let mem_lim = limits.and_then(|l| l.get("memory")).and_then(Value::as_str);

        if cpu_req.is_some() || cpu_lim.is_some() || mem_req.is_some() || mem_lim.is_some() {
            has_requests_or_limits = true;
        }

        // For Guaranteed:
        // CPU and memory limits must be set and > 0.
        // Requests must either equal limits, or if omitted, default to limits.
        let is_cpu_guaranteed = match (cpu_req, cpu_lim) {
            (Some(req), Some(lim)) => {
                let req_m = parse_cpu_quantity_milli(req);
                let lim_m = parse_cpu_quantity_milli(lim);
                req_m.is_some() && req_m == lim_m && req_m.unwrap_or(0) > 0
            },
            (None, Some(lim)) => parse_cpu_quantity_milli(lim).is_some_and(|m| m > 0),
            _ => false,
        };

        let is_mem_guaranteed = match (mem_req, mem_lim) {
            (Some(req), Some(lim)) => {
                let req_b = parse_memory_quantity_bytes(req);
                let lim_b = parse_memory_quantity_bytes(lim);
                req_b.is_some() && req_b == lim_b && req_b.unwrap_or(0) > 0
            },
            (None, Some(lim)) => parse_memory_quantity_bytes(lim).is_some_and(|b| b > 0),
            _ => false,
        };

        if !is_cpu_guaranteed || !is_mem_guaranteed {
            all_guaranteed = false;
        }
    }

    if all_guaranteed {
        PodQoSClass::Guaranteed
    } else if has_requests_or_limits {
        PodQoSClass::Burstable
    } else {
        PodQoSClass::BestEffort
    }
}

/// Checks whether a container in a pod is eligible for exclusive CPU allocation.
///
/// Returns `Some(cores_count)` if eligible, or `None` if the container runs in the shared pool.
/// Requirements:
/// 1. Pod must have Guaranteed `QoS`.
/// 2. Container must have an integer number of CPU cores requested (e.g. 1, 2, 1000m, 2000m).
#[must_use]
pub fn is_container_cpu_pinning_eligible(qos: PodQoSClass, container: &Value) -> Option<usize> {
    if qos != PodQoSClass::Guaranteed {
        return None;
    }

    let resources = container.get("resources")?;
    let cpu_str = resources
        .get("requests")
        .and_then(|r| r.get("cpu"))
        .or_else(|| resources.get("limits").and_then(|l| l.get("cpu")))?
        .as_str()?;

    let milli = parse_cpu_quantity_milli(cpu_str)?;
    if milli >= 1000 && milli % 1000 == 0 {
        Some((milli / 1000) as usize)
    } else {
        None
    }
}

/// CPU manager persisted state in `<root-dir>/cpu_manager_state`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuManagerState {
    #[serde(rename = "policyName")]
    pub policy_name: String,
    #[serde(rename = "defaultCpuSet")]
    pub default_cpuset: String,
    #[serde(rename = "entries", default)]
    pub entries: BTreeMap<String, String>,
}

/// CPU manager coordinating exclusive CPU core allocations and checkpoint persistence.
#[derive(Debug, Clone)]
pub struct CpuManager {
    policy: String,
    policy_options: BTreeMap<String, String>,
    reserved_cpus: BTreeSet<usize>,
    host_cpus: usize,
    checkpoint_path: PathBuf,
    allocations: Arc<std::sync::Mutex<BTreeMap<String, BTreeSet<usize>>>>,
}

impl CpuManager {
    #[must_use]
    pub fn new(
        policy: impl Into<String>,
        policy_options: BTreeMap<String, String>,
        reserved_cpus: BTreeSet<usize>,
        host_cpus: usize,
        checkpoint_path: PathBuf,
    ) -> Self {
        let policy_str = policy.into();
        let allocations = Arc::new(std::sync::Mutex::new(BTreeMap::new()));

        if policy_str == "static"
            && checkpoint_path.exists()
            && let Ok(content) = std::fs::read_to_string(&checkpoint_path)
            && let Ok(state) = serde_json::from_str::<CpuManagerState>(&content)
            && state.policy_name == "static"
            && let Ok(mut map) = allocations.lock()
        {
            for (container_id, cpuset_str) in state.entries {
                if let Ok(cpus) = parse_cpuset(&cpuset_str) {
                    map.insert(container_id, cpus);
                }
            }
        }

        Self {
            policy: policy_str,
            policy_options,
            reserved_cpus,
            host_cpus,
            checkpoint_path,
            allocations,
        }
    }

    #[must_use]
    pub fn from_options(options: &KubeletConfigOptions) -> Self {
        let host_cpus = detect_host_cpu_count();
        let reserved = if !options.reserved_cpus.is_empty() {
            parse_cpuset(&options.reserved_cpus).unwrap_or_default()
        } else if options.cpu_manager_policy == "static" {
            let count = options
                .system_reserved
                .get("cpu")
                .and_then(|q| parse_cpu_quantity_milli(q))
                .map_or(1, |m| usize::try_from(m.div_ceil(1000)).unwrap_or(1))
                .min(host_cpus)
                .max(1);
            (0..count).collect()
        } else {
            BTreeSet::new()
        };

        Self::new(
            &options.cpu_manager_policy,
            options.cpu_manager_policy_options.clone(),
            reserved,
            host_cpus,
            options.cpu_manager_checkpoint_path(),
        )
    }

    #[must_use]
    pub fn policy(&self) -> &str {
        &self.policy
    }

    #[must_use]
    pub fn host_cpus(&self) -> usize {
        self.host_cpus
    }

    #[must_use]
    pub fn reserved_cpus(&self) -> &BTreeSet<usize> {
        &self.reserved_cpus
    }

    #[must_use]
    pub fn policy_options(&self) -> &BTreeMap<String, String> {
        &self.policy_options
    }

    /// Returns the currently allocated exclusive CPUs for all containers.
    pub fn current_allocations(&self) -> BTreeMap<String, BTreeSet<usize>> {
        self.allocations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Drops all in-memory allocations (e.g. after checkpoint invalidation).
    pub fn reset(&self) {
        self.allocations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// Computes the shared CPU pool (all host CPUs excluding reserved and exclusively allocated cores).
    pub fn shared_pool(&self) -> BTreeSet<usize> {
        let map = self
            .allocations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut shared = BTreeSet::new();
        for cpu in 0..self.host_cpus {
            if !self.reserved_cpus.contains(&cpu) {
                let allocated = map.values().any(|set| set.contains(&cpu));
                if !allocated {
                    shared.insert(cpu);
                }
            }
        }
        shared
    }

    /// Allocates `count` exclusive CPUs for `container_key`.
    pub fn allocate_exclusive_cpus(
        &self,
        container_key: &str,
        count: usize,
    ) -> Result<BTreeSet<usize>, KubeletError> {
        if self.policy != "static" {
            return Ok(BTreeSet::new());
        }

        let mut map =
            self.allocations
                .lock()
                .map_err(|e| KubeletError::PodReconciliationFailed {
                    pod: container_key.to_string(),
                    reason: format!("CPU manager lock poisoned: {e}"),
                })?;

        if let Some(existing) = map.get(container_key) {
            return Ok(existing.clone());
        }

        let mut available: Vec<usize> = Vec::new();
        for cpu in 0..self.host_cpus {
            if !self.reserved_cpus.contains(&cpu) && !map.values().any(|set| set.contains(&cpu)) {
                available.push(cpu);
            }
        }

        if available.len() < count {
            return Err(KubeletError::PodReconciliationFailed {
                pod: container_key.to_string(),
                reason: format!(
                    "insufficient exclusive CPUs available: requested {count}, available {}",
                    available.len()
                ),
            });
        }

        let allocated: BTreeSet<usize> = available.into_iter().take(count).collect();
        map.insert(container_key.to_string(), allocated.clone());

        // Update checkpoint
        self.persist_checkpoint_locked(&map)?;

        Ok(allocated)
    }

    /// Releases exclusive CPUs for `container_key`.
    pub fn release_exclusive_cpus(&self, container_key: &str) -> Result<(), KubeletError> {
        if self.policy != "static" {
            return Ok(());
        }

        let mut map =
            self.allocations
                .lock()
                .map_err(|e| KubeletError::PodReconciliationFailed {
                    pod: container_key.to_string(),
                    reason: format!("CPU manager lock poisoned: {e}"),
                })?;

        if map.remove(container_key).is_some() {
            self.persist_checkpoint_locked(&map)?;
        }
        Ok(())
    }

    /// Releases all CPU allocations whose keys start with `prefix`.
    pub fn release_pod_cpus(&self, prefix: &str) -> Result<(), KubeletError> {
        if self.policy != "static" {
            return Ok(());
        }

        let mut map =
            self.allocations
                .lock()
                .map_err(|e| KubeletError::PodReconciliationFailed {
                    pod: prefix.to_string(),
                    reason: format!("CPU manager lock poisoned: {e}"),
                })?;

        let keys_to_remove: Vec<String> = map
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();

        if !keys_to_remove.is_empty() {
            for k in keys_to_remove {
                map.remove(&k);
            }
            self.persist_checkpoint_locked(&map)?;
        }
        Ok(())
    }

    fn persist_checkpoint_locked(
        &self,
        map: &BTreeMap<String, BTreeSet<usize>>,
    ) -> Result<(), KubeletError> {
        let mut shared = BTreeSet::new();
        for cpu in 0..self.host_cpus {
            if !self.reserved_cpus.contains(&cpu) {
                let allocated = map.values().any(|set| set.contains(&cpu));
                if !allocated {
                    shared.insert(cpu);
                }
            }
        }

        let mut entries = BTreeMap::new();
        for (k, set) in map {
            entries.insert(k.clone(), format_cpuset(set));
        }

        let state = CpuManagerState {
            policy_name: self.policy.clone(),
            default_cpuset: format_cpuset(&shared),
            entries,
        };

        if let Some(parent) = self.checkpoint_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let json = serde_json::to_string_pretty(&state).map_err(|e| {
            KubeletError::InvalidConfiguration {
                field: "checkpoint".to_string(),
                reason: format!("failed to serialize cpu_manager_state: {e}"),
            }
        })?;

        std::fs::write(&self.checkpoint_path, json).map_err(|e| {
            KubeletError::InvalidConfiguration {
                field: "checkpoint".to_string(),
                reason: format!("failed to write cpu_manager_state: {e}"),
            }
        })?;

        Ok(())
    }
}

/// Diagnostic report for an active container that needs restart after a CPU manager checkpoint invalidation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadRestartReport {
    pub namespace: String,
    pub pod_name: String,
    pub container_name: String,
    pub container_id: String,
    pub reason: String,
}

pub(crate) fn safe_volume_path(vol_dir: &Path, rel: &str) -> Result<PathBuf, KubeletError> {
    let p = Path::new(rel);
    if rel.is_empty()
        || p.is_absolute()
        || p.components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(KubeletError::InvalidConfiguration {
            field: "volume.items.path".into(),
            reason: format!("invalid volume path '{rel}'"),
        });
    }
    Ok(vol_dir.join(p))
}

pub(crate) fn write_volume_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, content)
}

/// Applies a Kubernetes file `mode` (decimal, e.g. `420` for `0644`) to a staged file.
pub(crate) fn chmod_volume_file(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777));
}

/// Effective mode for one staged file: per-item `mode`, else the volume
/// `defaultMode`, else the Kubernetes default (`0644` for config/secret data).
pub(crate) fn volume_file_mode(item: Option<&Value>, vol_spec: &Value) -> u32 {
    item.and_then(|item| item.get("mode"))
        .or_else(|| vol_spec.get("defaultMode"))
        .and_then(Value::as_u64)
        .and_then(|mode| u32::try_from(mode).ok())
        .map_or(0o644, |mode| mode & 0o777)
}

/// Reads `pod.spec.securityContext.fsGroup` as a gid, if valid.
pub(crate) fn pod_fs_group(pod: &Value) -> Option<u32> {
    let group = pod.pointer("/spec/securityContext/fsGroup")?.as_u64()?;
    u32::try_from(group).ok()
}

/// Gives a staged volume directory to a pod `fsGroup`, like upstream's
/// `SetVolumeOwnership`: every entry is group-chowned (without following
/// symlinks) and group read/write is added so non-root containers can use
/// `emptyDir` and projected volumes. Skips the walk when the root already
/// carries the group (`OnRootMismatch` behaviour).
pub(crate) fn apply_fs_group_ownership(vol_dir: &Path, fs_group: u32) -> Result<(), KubeletError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root_meta = std::fs::symlink_metadata(vol_dir).map_err(KubeletError::Io)?;
    if root_meta.gid() == fs_group {
        return Ok(());
    }
    let mut stack = vec![vol_dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        chown_group(&path, fs_group)?;
        let mut mode = meta.permissions().mode();
        if meta.is_dir() {
            mode |= 0o070;
        } else {
            mode |= 0o060;
            if mode & 0o100 != 0 {
                mode |= 0o010;
            }
        }
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
        if meta.is_dir() {
            let Ok(entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.flatten() {
                stack.push(entry.path());
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn chown_group(path: &Path, gid: u32) -> Result<(), KubeletError> {
    rustix::fs::chown(path, None, Some(rustix::fs::Gid::from_raw(gid)))
        .map_err(|errno| KubeletError::Io(std::io::Error::from(errno)))
}

#[cfg(not(unix))]
fn chown_group(_path: &Path, _gid: u32) -> Result<(), KubeletError> {
    Ok(())
}

pub(crate) fn stage_secret_files(
    vol_dir: &Path,
    vol_spec: &Value,
    sec_obj: &Value,
) -> Result<(), KubeletError> {
    let data_map = sec_obj.get("data").and_then(Value::as_object);
    let string_data_map = sec_obj.get("stringData").and_then(Value::as_object);

    if let Some(items) = vol_spec.get("items").and_then(Value::as_array) {
        for item in items {
            let key = item.get("key").and_then(Value::as_str).unwrap_or("");
            let path = item.get("path").and_then(Value::as_str).unwrap_or(key);
            let file_path = safe_volume_path(vol_dir, path)?;
            let mode = volume_file_mode(Some(item), vol_spec);
            if let Some(val) = data_map.and_then(|m| m.get(key)).and_then(Value::as_str) {
                let bytes = diorama_pki::base64_decode(val.trim())
                    .unwrap_or_else(|_| val.as_bytes().to_vec());
                write_volume_file(&file_path, &bytes)?;
                chmod_volume_file(&file_path, mode);
            } else if let Some(val) = string_data_map
                .and_then(|m| m.get(key))
                .and_then(Value::as_str)
            {
                write_volume_file(&file_path, val.as_bytes())?;
                chmod_volume_file(&file_path, mode);
            }
        }
    } else {
        let mode = volume_file_mode(None, vol_spec);
        if let Some(data) = data_map {
            for (key, val_v) in data {
                if let Some(val_str) = val_v.as_str() {
                    let file_path = safe_volume_path(vol_dir, key)?;
                    let bytes = diorama_pki::base64_decode(val_str.trim())
                        .unwrap_or_else(|_| val_str.as_bytes().to_vec());
                    write_volume_file(&file_path, &bytes)?;
                    chmod_volume_file(&file_path, mode);
                }
            }
        }
        if let Some(str_data) = string_data_map {
            for (key, val_v) in str_data {
                if let Some(val_str) = val_v.as_str() {
                    let file_path = safe_volume_path(vol_dir, key)?;
                    write_volume_file(&file_path, val_str.as_bytes())?;
                    chmod_volume_file(&file_path, mode);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn stage_configmap_files(
    vol_dir: &Path,
    vol_spec: &Value,
    cm_obj: &Value,
) -> Result<(), KubeletError> {
    let data_map = cm_obj.get("data").and_then(Value::as_object);
    let binary_data_map = cm_obj.get("binaryData").and_then(Value::as_object);

    if let Some(items) = vol_spec.get("items").and_then(Value::as_array) {
        for item in items {
            let key = item.get("key").and_then(Value::as_str).unwrap_or("");
            let path = item.get("path").and_then(Value::as_str).unwrap_or(key);
            let file_path = safe_volume_path(vol_dir, path)?;
            let mode = volume_file_mode(Some(item), vol_spec);
            if let Some(val) = data_map.and_then(|m| m.get(key)).and_then(Value::as_str) {
                write_volume_file(&file_path, val.as_bytes())?;
                chmod_volume_file(&file_path, mode);
            } else if let Some(val) = binary_data_map
                .and_then(|m| m.get(key))
                .and_then(Value::as_str)
            {
                let bytes = diorama_pki::base64_decode(val.trim())
                    .unwrap_or_else(|_| val.as_bytes().to_vec());
                write_volume_file(&file_path, &bytes)?;
                chmod_volume_file(&file_path, mode);
            }
        }
    } else {
        let mode = volume_file_mode(None, vol_spec);
        if let Some(data) = data_map {
            for (key, val_v) in data {
                if let Some(val_str) = val_v.as_str() {
                    let file_path = safe_volume_path(vol_dir, key)?;
                    write_volume_file(&file_path, val_str.as_bytes())?;
                    chmod_volume_file(&file_path, mode);
                }
            }
        }
        if let Some(bin_data) = binary_data_map {
            for (key, val_v) in bin_data {
                if let Some(val_str) = val_v.as_str() {
                    let file_path = safe_volume_path(vol_dir, key)?;
                    let bytes = diorama_pki::base64_decode(val_str.trim())
                        .unwrap_or_else(|_| val_str.as_bytes().to_vec());
                    write_volume_file(&file_path, &bytes)?;
                    chmod_volume_file(&file_path, mode);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn stage_projected_sa_token(
    vol_dir: &Path,
    namespace: &str,
    pod: &Value,
    sa_tok: &Value,
    apiserver: Option<&Arc<ApiserverService>>,
) -> Result<(), KubeletError> {
    let rel_path = sa_tok
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("token");
    let audience = sa_tok
        .get("audience")
        .and_then(Value::as_str)
        .unwrap_or("api");
    let lifetime = sa_tok
        .get("expirationSeconds")
        .and_then(Value::as_u64)
        .unwrap_or(3600);
    let sa_name = pod
        .get("spec")
        .and_then(|s| s.get("serviceAccountName"))
        .and_then(Value::as_str)
        .unwrap_or("default");
    let pod_name = pod
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let token_str = if let Some(srv) = apiserver {
        srv.issue_service_account_token(
            namespace,
            sa_name,
            &[audience.to_string()],
            std::time::Duration::from_secs(lifetime),
        )
        .map_err(|e| KubeletError::PodReconciliationFailed {
            pod: pod_name.to_string(),
            reason: format!("failed to issue service account token for {namespace}/{sa_name}: {e}"),
        })?
    } else {
        format!("mock-token-{namespace}-{sa_name}")
    };

    let token_path = safe_volume_path(vol_dir, rel_path)?;
    write_volume_file(&token_path, token_str.as_bytes())?;

    let ns_path = safe_volume_path(vol_dir, "namespace")?;
    if !ns_path.exists() {
        let _ = write_volume_file(&ns_path, namespace.as_bytes());
    }

    let ca_path = safe_volume_path(vol_dir, "ca.crt")?;
    if !ca_path.exists() {
        let ca_bytes = apiserver
            .and_then(|srv| {
                if srv.config().client_ca_file.exists() {
                    std::fs::read(&srv.config().client_ca_file).ok()
                } else {
                    None
                }
            })
            .unwrap_or_else(|| b"mock-ca-cert".to_vec());
        let _ = write_volume_file(&ca_path, &ca_bytes);
    }

    Ok(())
}

pub(crate) fn stage_projected_downward_api(
    vol_dir: &Path,
    namespace: &str,
    pod: &Value,
    items: &[Value],
) -> Result<(), KubeletError> {
    for item in items {
        let path = item.get("path").and_then(Value::as_str).unwrap_or("");
        let field_path = item
            .get("fieldRef")
            .and_then(|f| f.get("fieldPath"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let val = match field_path {
            "metadata.name" => pod
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
                .unwrap_or(""),
            "metadata.namespace" => namespace,
            "metadata.uid" => pod
                .get("metadata")
                .and_then(|m| m.get("uid"))
                .and_then(Value::as_str)
                .unwrap_or(""),
            _ => "",
        };

        let target = safe_volume_path(vol_dir, path)?;
        write_volume_file(&target, val.as_bytes())?;
    }
    Ok(())
}

pub(crate) fn check_pod_restart_need(
    pod: &Value,
    node_name: &str,
    provider_name: &str,
    namespace: &str,
) -> Vec<WorkloadRestartReport> {
    let mut reports = Vec::new();
    let assigned_node = pod
        .get("spec")
        .and_then(|s| s.get("nodeName"))
        .and_then(Value::as_str);
    if assigned_node != Some(node_name) {
        return reports;
    }

    let phase = pod
        .get("status")
        .and_then(|s| s.get("phase"))
        .and_then(Value::as_str);
    if phase != Some("Running") {
        return reports;
    }

    let qos = determine_pod_qos(pod);
    let pod_name = pod
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let Some(containers) = pod
        .get("spec")
        .and_then(|s| s.get("containers"))
        .and_then(Value::as_array)
    else {
        return reports;
    };

    for c in containers {
        let c_name = c.get("name").and_then(Value::as_str).unwrap_or("unknown");
        if is_container_cpu_pinning_eligible(qos, c).is_some() {
            let c_id = pod
                .get("status")
                .and_then(|s| s.get("containerStatuses"))
                .and_then(Value::as_array)
                .and_then(|cs| {
                    cs.iter()
                        .find(|s| s.get("name").and_then(Value::as_str) == Some(c_name))
                })
                .and_then(|s| s.get("containerID"))
                .and_then(Value::as_str)
                .map_or_else(|| format!("{provider_name}://unknown"), ToString::to_string);
            let reason = format!(
                "CPU manager checkpoint invalidated; surviving external container '{c_name}' in pod '{namespace}/{pod_name}' runs in shared pool until restarted"
            );
            eprintln!("workload restart required: {reason}");
            reports.push(WorkloadRestartReport {
                namespace: namespace.to_string(),
                pod_name: pod_name.to_string(),
                container_name: c_name.to_string(),
                container_id: c_id,
                reason,
            });
        }
    }

    reports
}

#[cfg(test)]
mod tests {
    use super::{apply_fs_group_ownership, pod_fs_group, volume_file_mode};
    use serde_json::json;

    #[test]
    fn file_mode_prefers_item_over_default() {
        let vol = json!({ "defaultMode": 420 });
        assert_eq!(volume_file_mode(None, &vol), 0o644);
        assert_eq!(volume_file_mode(Some(&json!({ "mode": 256 })), &vol), 0o400);
        assert_eq!(volume_file_mode(None, &json!({})), 0o644);
        // Out-of-range bits are masked to permission bits.
        assert_eq!(
            volume_file_mode(None, &json!({ "defaultMode": 0o100_644 })),
            0o644
        );
    }

    #[test]
    fn fs_group_parses_valid_gids_only() {
        assert_eq!(
            pod_fs_group(&json!({ "spec": { "securityContext": { "fsGroup": 2000 } } })),
            Some(2000)
        );
        assert_eq!(pod_fs_group(&json!({ "spec": {} })), None);
        assert_eq!(
            pod_fs_group(&json!({ "spec": { "securityContext": { "fsGroup": -1 } } })),
            None
        );
    }

    #[test]
    fn fs_group_ownership_skips_matching_root() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("diorama-fsgroup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let gid = std::fs::symlink_metadata(&dir).unwrap().gid();
        // The root already carries the group, so no chown walk runs.
        apply_fs_group_ownership(&dir, gid).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
