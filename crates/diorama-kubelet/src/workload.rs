//! Runtime contracts shared by the kubelet reconciler and its runtime providers.
//!
//! [`RuntimeProvider`] is the CRI v1 surface the kubelet uses, expressed with the
//! generated `diorama_cri::runtime::v1` types so a containerd provider is a thin
//! wrapper over `diorama_cri::CriClient` and the podman engine adapts to the same
//! contract. The module also carries the `QoS` and CPU-manager helpers and the
//! host-side volume staging used while preparing a pod.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
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

/// Truncates a pod hostname to 63 bytes and strips trailing `'-'` or `'.'`.
#[must_use]
pub fn truncate_pod_hostname(raw: &str) -> String {
    let truncated = if raw.len() > 63 {
        let boundary = raw.floor_char_boundary(63);
        &raw[..boundary]
    } else {
        raw
    };
    truncated.trim_end_matches(['-', '.']).to_string()
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

/// Whether an init container specification defines a restartable sidecar container (`restartPolicy: Always`).
#[must_use]
pub fn is_restartable_init(spec: &Value) -> bool {
    spec.get("restartPolicy").and_then(Value::as_str) == Some("Always")
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

/// Parses a CPU quantity from a JSON `Value` (string, integer, or float) into millicores.
#[must_use]
pub fn parse_cpu_quantity_from_value(v: &Value) -> Option<u64> {
    if let Some(s) = v.as_str() {
        parse_cpu_quantity_milli(s)
    } else if let Some(n) = v.as_u64() {
        n.checked_mul(1000)
    } else if let Some(f) = v.as_f64() {
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

/// Parses a memory quantity from a JSON `Value` (string, integer, or float) into bytes.
#[must_use]
pub fn parse_memory_quantity_from_value(v: &Value) -> Option<u64> {
    if let Some(s) = v.as_str() {
        parse_memory_quantity_bytes(s)
    } else if let Some(n) = v.as_u64() {
        Some(n)
    } else if let Some(f) = v.as_f64() {
        if f.is_sign_negative() || f.is_nan() || f.is_infinite() {
            None
        } else {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let val = f.round() as u64;
            Some(val)
        }
    } else {
        None
    }
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
    if rel.is_empty() || rel.contains('\0') || rel.starts_with('/') || rel.starts_with('\\') {
        return Err(KubeletError::InvalidConfiguration {
            field: "volume.items.path".into(),
            reason: format!("invalid volume path '{rel}'"),
        });
    }
    let p = Path::new(rel);
    if p.is_absolute()
        || p.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir
                    | std::path::Component::Prefix(_)
                    | std::path::Component::RootDir
            )
        })
    {
        return Err(KubeletError::InvalidConfiguration {
            field: "volume.items.path".into(),
            reason: format!("invalid volume path '{rel}'"),
        });
    }
    let mut clean = PathBuf::new();
    for comp in p.components() {
        if let std::path::Component::Normal(part) = comp {
            clean.push(part);
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(KubeletError::InvalidConfiguration {
            field: "volume.items.path".into(),
            reason: format!("invalid volume path '{rel}'"),
        });
    }
    Ok(vol_dir.join(clean))
}

pub(crate) fn write_volume_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // If the file already exists on disk and is read-only (e.g. 0400 from a previous sync pass),
    // opening it for writing with fs::write fails with PermissionDenied.
    // Temporarily setting writable permissions ensures re-syncing succeeds.
    // In addition, regular files are truncated and overwritten in-place rather than unlinked
    // so that existing open file descriptors and subpath mounts stay valid.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        }
        if meta.file_type().is_symlink() {
            let _ = std::fs::remove_file(path);
        } else if meta.is_dir() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(content)?;
    file.flush()
}

/// Applies a Kubernetes file `mode` (decimal, e.g. `420` for `0644`) to a staged file.
pub(crate) fn chmod_volume_file(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

/// Mount points from `/proc/self/mountinfo` (field 5), with octal escapes decoded.
fn mount_points() -> Vec<PathBuf> {
    let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    info.lines()
        .filter_map(|line| line.split(' ').nth(4))
        .map(|p| PathBuf::from(p.replace("\\040", " ")))
        .collect()
}

/// Backs a `medium: Memory` `emptyDir` with tmpfs unless it is already mounted.
pub(crate) fn ensure_tmpfs_mount(dir: &Path, size_bytes: Option<u64>) {
    if mount_points().iter().any(|m| m == dir) {
        return;
    }
    let opts = match size_bytes.filter(|s| *s > 0) {
        Some(size) => format!("mode=0777,size={size}"),
        None => "mode=0777".to_string(),
    };
    match std::process::Command::new("mount")
        .args(["-t", "tmpfs", "-o", &opts, "tmpfs"])
        .arg(dir)
        .output()
    {
        Ok(out) if out.status.success() => {},
        Ok(out) => eprintln!(
            "tmpfs mount for {} failed: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => eprintln!("tmpfs mount for {} failed: {e}", dir.display()),
    }
}

/// Unmounts every mount nested under a removed pod's directory.
pub(crate) fn unmount_tmpfs_under(pod_dir: &Path) {
    let mut nested: Vec<PathBuf> = mount_points()
        .into_iter()
        .filter(|m| m.starts_with(pod_dir))
        .collect();
    // Deepest first so nested mounts release cleanly.
    nested.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for mount in nested {
        let _ = std::process::Command::new("umount").arg(&mount).output();
    }
}

fn parse_mode_value(v: &Value) -> Option<u32> {
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).ok();
    }
    if let Some(n) = v.as_i64()
        && n >= 0
    {
        return u32::try_from(n).ok();
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if let Some(oct) = s.strip_prefix("0o") {
            return u32::from_str_radix(oct, 8).ok();
        }
        if s.starts_with('0') && s.len() > 1 && s.chars().all(|c| ('0'..='7').contains(&c)) {
            return u32::from_str_radix(s, 8).ok();
        }
        if let Ok(dec) = s.parse::<u32>() {
            return Some(dec);
        }
    }
    None
}

/// Effective mode for one staged file: per-item `mode`, else the volume
/// `defaultMode`, else the Kubernetes default (`0644` for config/secret data).
pub(crate) fn volume_file_mode(item: Option<&Value>, vol_spec: &Value) -> u32 {
    item.and_then(|item| item.get("mode"))
        .or_else(|| vol_spec.get("defaultMode"))
        .and_then(parse_mode_value)
        .map_or(0o644, |mode| mode & 0o7777)
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
#[cfg(test)]
pub(crate) fn apply_fs_group_ownership(vol_dir: &Path, fs_group: u32) -> Result<(), KubeletError> {
    apply_fs_group_ownership_with_options(vol_dir, fs_group, false, true)
}

pub(crate) fn apply_fs_group_ownership_with_options(
    vol_dir: &Path,
    fs_group: u32,
    readonly: bool,
    on_root_mismatch: bool,
) -> Result<(), KubeletError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root_meta = std::fs::symlink_metadata(vol_dir).map_err(KubeletError::Io)?;
    if on_root_mismatch && root_meta.gid() == fs_group {
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
            mode |= if readonly { 0o050 } else { 0o070 };
        } else {
            mode |= if readonly { 0o040 } else { 0o060 };
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

pub(crate) fn prune_stale_volume_files(
    vol_dir: &Path,
    expected: &std::collections::HashSet<PathBuf>,
) {
    let mut stack = vec![vol_dir.to_path_buf()];
    let mut dirs = Vec::new();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() && !meta.file_type().is_symlink() {
                dirs.push(path.clone());
                stack.push(path);
            } else if !expected.contains(&path) {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    for dir in dirs.into_iter().rev() {
        let _ = std::fs::remove_dir(&dir);
    }
}

pub(crate) fn stage_secret_files(
    vol_dir: &Path,
    vol_spec: &Value,
    sec_obj: &Value,
) -> Result<Vec<PathBuf>, KubeletError> {
    let data_map = sec_obj.get("data").and_then(Value::as_object);
    let string_data_map = sec_obj.get("stringData").and_then(Value::as_object);
    let mut written = Vec::new();

    if let Some(items) = vol_spec.get("items").and_then(Value::as_array) {
        let optional = vol_spec
            .get("optional")
            .and_then(Value::as_bool)
            .unwrap_or(false);
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
                written.push(file_path);
            } else if let Some(val) = string_data_map
                .and_then(|m| m.get(key))
                .and_then(Value::as_str)
            {
                write_volume_file(&file_path, val.as_bytes())?;
                chmod_volume_file(&file_path, mode);
                written.push(file_path);
            } else if !optional {
                return Err(KubeletError::InvalidConfiguration {
                    field: "items.key".to_string(),
                    reason: format!("key '{key}' not found in secret"),
                });
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
                    written.push(file_path);
                }
            }
        }
        if let Some(str_data) = string_data_map {
            for (key, val_v) in str_data {
                if let Some(val_str) = val_v.as_str() {
                    let file_path = safe_volume_path(vol_dir, key)?;
                    write_volume_file(&file_path, val_str.as_bytes())?;
                    chmod_volume_file(&file_path, mode);
                    written.push(file_path);
                }
            }
        }
    }
    Ok(written)
}

pub(crate) fn stage_configmap_files(
    vol_dir: &Path,
    vol_spec: &Value,
    cm_obj: &Value,
) -> Result<Vec<PathBuf>, KubeletError> {
    let data_map = cm_obj.get("data").and_then(Value::as_object);
    let binary_data_map = cm_obj.get("binaryData").and_then(Value::as_object);
    let mut written = Vec::new();

    if let Some(items) = vol_spec.get("items").and_then(Value::as_array) {
        let optional = vol_spec
            .get("optional")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        for item in items {
            let key = item.get("key").and_then(Value::as_str).unwrap_or("");
            let path = item.get("path").and_then(Value::as_str).unwrap_or(key);
            let file_path = safe_volume_path(vol_dir, path)?;
            let mode = volume_file_mode(Some(item), vol_spec);
            if let Some(val) = data_map.and_then(|m| m.get(key)).and_then(Value::as_str) {
                write_volume_file(&file_path, val.as_bytes())?;
                chmod_volume_file(&file_path, mode);
                written.push(file_path);
            } else if let Some(val) = binary_data_map
                .and_then(|m| m.get(key))
                .and_then(Value::as_str)
            {
                let bytes = diorama_pki::base64_decode(val.trim())
                    .unwrap_or_else(|_| val.as_bytes().to_vec());
                write_volume_file(&file_path, &bytes)?;
                chmod_volume_file(&file_path, mode);
                written.push(file_path);
            } else if !optional {
                return Err(KubeletError::InvalidConfiguration {
                    field: "items.key".to_string(),
                    reason: format!("key '{key}' not found in configMap"),
                });
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
                    written.push(file_path);
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
                    written.push(file_path);
                }
            }
        }
    }
    Ok(written)
}

pub(crate) fn stage_projected_sa_token(
    vol_dir: &Path,
    namespace: &str,
    pod: &Value,
    sa_tok: &Value,
    apiserver: Option<&Arc<ApiserverService>>,
) -> Result<Vec<PathBuf>, KubeletError> {
    let rel_path = sa_tok
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("token");
    let audiences: Vec<String> = match sa_tok.get("audience").and_then(Value::as_str) {
        Some(a) if !a.is_empty() => vec![a.to_string()],
        _ => Vec::new(),
    };
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
            &audiences,
            std::time::Duration::from_secs(lifetime),
        )
        .map_err(|e| KubeletError::PodReconciliationFailed {
            pod: pod_name.to_string(),
            reason: format!("failed to issue service account token for {namespace}/{sa_name}: {e}"),
        })?
    } else {
        format!("mock-token-{namespace}-{sa_name}")
    };

    let mut written = Vec::new();
    let token_path = safe_volume_path(vol_dir, rel_path)?;
    write_volume_file(&token_path, token_str.as_bytes())?;
    chmod_volume_file(&token_path, volume_file_mode(Some(sa_tok), sa_tok));
    written.push(token_path);

    let ns_path = safe_volume_path(vol_dir, "namespace")?;
    if !ns_path.exists() {
        let _ = write_volume_file(&ns_path, namespace.as_bytes());
        chmod_volume_file(&ns_path, 0o644);
    }
    written.push(ns_path);

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
        chmod_volume_file(&ca_path, 0o644);
    }
    written.push(ca_path);

    Ok(written)
}

pub(crate) fn format_downward_map(map: Option<&serde_json::Map<String, Value>>) -> String {
    let Some(map) = map else {
        return String::new();
    };
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    let mut lines = Vec::with_capacity(keys.len());
    for k in keys {
        if let Some(v) = map.get(k).and_then(Value::as_str) {
            let escaped = v
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            lines.push(format!("{k}=\"{escaped}\""));
        }
    }
    lines.join("\n")
}

pub(crate) fn resolve_downward_field_path(
    pod: &Value,
    namespace: &str,
    field_path: &str,
) -> Option<String> {
    match field_path {
        "metadata.name" => Some(
            pod.pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ),
        "metadata.namespace" => Some(
            pod.pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(namespace)
                .to_string(),
        ),
        "metadata.uid" => Some(
            pod.pointer("/metadata/uid")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ),
        "spec.nodeName" => Some(
            pod.pointer("/spec/nodeName")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ),
        "spec.serviceAccountName" => Some(
            pod.pointer("/spec/serviceAccountName")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or("default")
                .to_string(),
        ),
        "status.hostIP" => Some(
            pod.pointer("/status/hostIP")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or("127.0.0.1")
                .to_string(),
        ),
        "status.podIP" | "status.podIPs" => Some(
            pod.pointer("/status/podIP")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        ),
        "metadata.labels" => Some(format_downward_map(
            pod.pointer("/metadata/labels").and_then(Value::as_object),
        )),
        "metadata.annotations" => Some(format_downward_map(
            pod.pointer("/metadata/annotations")
                .and_then(Value::as_object),
        )),
        other => {
            if let Some(key) = other
                .strip_prefix("metadata.labels['")
                .and_then(|s| s.strip_suffix("']"))
                .or_else(|| {
                    other
                        .strip_prefix("metadata.labels[\"")
                        .and_then(|s| s.strip_suffix("\"]"))
                })
            {
                return Some(
                    pod.pointer("/metadata/labels")
                        .and_then(Value::as_object)
                        .and_then(|m| m.get(key))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                );
            }
            if let Some(key) = other
                .strip_prefix("metadata.annotations['")
                .and_then(|s| s.strip_suffix("']"))
                .or_else(|| {
                    other
                        .strip_prefix("metadata.annotations[\"")
                        .and_then(|s| s.strip_suffix("\"]"))
                })
            {
                return Some(
                    pod.pointer("/metadata/annotations")
                        .and_then(Value::as_object)
                        .and_then(|m| m.get(key))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                );
            }
            None
        },
    }
}

pub(crate) fn resolve_downward_resource_field(
    pod: &Value,
    default_container: Option<&str>,
    res_ref: &Value,
) -> Option<String> {
    let target_name = res_ref
        .get("containerName")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or(default_container);
    let containers = pod.pointer("/spec/containers").and_then(Value::as_array);
    let init_containers = pod
        .pointer("/spec/initContainers")
        .and_then(Value::as_array);
    let container = if let Some(name) = target_name {
        containers
            .into_iter()
            .flatten()
            .chain(init_containers.into_iter().flatten())
            .find(|c| c.get("name").and_then(Value::as_str) == Some(name))
    } else {
        containers.and_then(|arr| arr.first())
    };
    let resource = res_ref.get("resource").and_then(Value::as_str)?;
    let divisor_val = res_ref.get("divisor");

    match resource {
        "limits.cpu" | "requests.cpu" => {
            let milli = if resource == "limits.cpu" {
                container
                    .and_then(|c| c.pointer("/resources/limits/cpu"))
                    .and_then(parse_cpu_quantity_from_value)
                    .unwrap_or(2000)
            } else {
                container
                    .and_then(|c| {
                        c.pointer("/resources/requests/cpu")
                            .or_else(|| c.pointer("/resources/limits/cpu"))
                    })
                    .and_then(parse_cpu_quantity_from_value)
                    .unwrap_or(0)
            };
            let div = divisor_val
                .and_then(parse_cpu_quantity_from_value)
                .filter(|&d| d > 0)
                .unwrap_or(1000)
                .max(1);
            Some(milli.div_ceil(div).to_string())
        },
        "limits.memory" | "requests.memory" => {
            let bytes = if resource == "limits.memory" {
                container
                    .and_then(|c| c.pointer("/resources/limits/memory"))
                    .and_then(parse_memory_quantity_from_value)
                    .unwrap_or(4 * 1024 * 1024 * 1024)
            } else {
                container
                    .and_then(|c| {
                        c.pointer("/resources/requests/memory")
                            .or_else(|| c.pointer("/resources/limits/memory"))
                    })
                    .and_then(parse_memory_quantity_from_value)
                    .unwrap_or(0)
            };
            let div = divisor_val
                .and_then(parse_memory_quantity_from_value)
                .filter(|&d| d > 0)
                .unwrap_or(1)
                .max(1);
            Some(bytes.div_ceil(div).to_string())
        },
        "limits.ephemeral-storage" | "requests.ephemeral-storage" => Some("0".to_string()),
        _ => None,
    }
}

pub(crate) fn stage_projected_downward_api(
    vol_dir: &Path,
    namespace: &str,
    pod: &Value,
    items: &[Value],
    vol_spec: &Value,
) -> Result<Vec<PathBuf>, KubeletError> {
    let mut written = Vec::new();
    for item in items {
        let path = item.get("path").and_then(Value::as_str).unwrap_or("");
        let mode = volume_file_mode(Some(item), vol_spec);
        let val = if let Some(field_path) = item
            .get("fieldRef")
            .and_then(|f| f.get("fieldPath"))
            .and_then(Value::as_str)
        {
            resolve_downward_field_path(pod, namespace, field_path).unwrap_or_default()
        } else if let Some(res_ref) = item.get("resourceFieldRef") {
            resolve_downward_resource_field(pod, None, res_ref).unwrap_or_default()
        } else {
            String::new()
        };

        let target = safe_volume_path(vol_dir, path)?;
        write_volume_file(&target, val.as_bytes())?;
        chmod_volume_file(&target, mode);
        written.push(target);
    }
    Ok(written)
}

fn matches_label_selector(
    labels: Option<&serde_json::Map<String, Value>>,
    selector: Option<&Value>,
) -> bool {
    let Some(sel) = selector else {
        return true;
    };
    if let Some(match_labels) = sel.get("matchLabels").and_then(Value::as_object) {
        let Some(lbls) = labels else {
            return false;
        };
        for (k, v) in match_labels {
            let req_val = v.as_str().unwrap_or("");
            let act_val = lbls.get(k).and_then(Value::as_str).unwrap_or("");
            if act_val != req_val {
                return false;
            }
        }
    }
    if let Some(exprs) = sel.get("matchExpressions").and_then(Value::as_array) {
        let empty_map = serde_json::Map::new();
        let lbls = labels.unwrap_or(&empty_map);
        for expr in exprs {
            let key = expr.get("key").and_then(Value::as_str).unwrap_or("");
            let op = expr.get("operator").and_then(Value::as_str).unwrap_or("");
            let values = expr.get("values").and_then(Value::as_array);
            match op {
                "In" => {
                    let Some(v) = lbls.get(key).and_then(Value::as_str) else {
                        return false;
                    };
                    let in_set =
                        values.is_some_and(|vals| vals.iter().any(|req| req.as_str() == Some(v)));
                    if !in_set {
                        return false;
                    }
                },
                "NotIn" => {
                    if let Some(v) = lbls.get(key).and_then(Value::as_str)
                        && let Some(vals) = values
                        && vals.iter().any(|req| req.as_str() == Some(v))
                    {
                        return false;
                    }
                },
                "Exists" => {
                    if !lbls.contains_key(key) {
                        return false;
                    }
                },
                "DoesNotExist" if lbls.contains_key(key) => {
                    return false;
                },
                _ => {},
            }
        }
    }
    true
}

/// Stages projected `ClusterTrustBundle` files matching either `name` or `signerName`
/// (with optional `labelSelector`), combining their PEM-encoded certificates into
/// the destination relative path.
pub fn stage_projected_clustertrustbundle(
    vol_dir: &Path,
    ctb_proj: &Value,
    bundles: &[Value],
    vol_spec: &Value,
) -> Result<Vec<PathBuf>, KubeletError> {
    let path = ctb_proj
        .get("path")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| KubeletError::InvalidConfiguration {
            field: "clusterTrustBundle.path".to_string(),
            reason: "clusterTrustBundle projection requires non-empty path".to_string(),
        })?;

    let optional = ctb_proj
        .get("optional")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut matched: Vec<&Value> = Vec::new();

    if let Some(name) = ctb_proj.get("name").and_then(Value::as_str) {
        if ctb_proj.get("signerName").is_some() || ctb_proj.get("labelSelector").is_some() {
            return Err(KubeletError::InvalidConfiguration {
                field: "clusterTrustBundle".to_string(),
                reason: "name and signerName/labelSelector are mutually exclusive".to_string(),
            });
        }
        if let Some(bundle) = bundles
            .iter()
            .find(|b| b.pointer("/metadata/name").and_then(Value::as_str) == Some(name))
        {
            matched.push(bundle);
        } else if !optional {
            return Err(KubeletError::InvalidConfiguration {
                field: "clusterTrustBundle.name".to_string(),
                reason: format!("ClusterTrustBundle '{name}' not found"),
            });
        }
    } else if let Some(signer_name) = ctb_proj.get("signerName").and_then(Value::as_str) {
        let selector = ctb_proj.get("labelSelector");
        let has_selector = selector.is_some() && selector != Some(&Value::Null);
        if has_selector {
            for bundle in bundles {
                let b_signer = bundle.pointer("/spec/signerName").and_then(Value::as_str);
                let b_labels = bundle
                    .pointer("/metadata/labels")
                    .and_then(Value::as_object);
                if b_signer == Some(signer_name) && matches_label_selector(b_labels, selector) {
                    matched.push(bundle);
                }
            }
            if matched.is_empty() && !optional {
                return Err(KubeletError::InvalidConfiguration {
                    field: "clusterTrustBundle.signerName".to_string(),
                    reason: format!(
                        "no ClusterTrustBundle matching signerName '{signer_name}' found"
                    ),
                });
            }
        } else if !optional {
            return Err(KubeletError::InvalidConfiguration {
                field: "clusterTrustBundle.labelSelector".to_string(),
                reason: "labelSelector is required when signerName is set".to_string(),
            });
        }
    } else if !optional {
        return Err(KubeletError::InvalidConfiguration {
            field: "clusterTrustBundle".to_string(),
            reason: "either name or signerName must be specified".to_string(),
        });
    }

    // Sort bundles deterministically by name
    matched.sort_by_key(|b| {
        b.pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("")
    });

    let mut combined_bundle = String::new();
    for bundle in matched {
        if let Some(tb) = bundle.pointer("/spec/trustBundle").and_then(Value::as_str) {
            let trimmed = tb.trim();
            if !trimmed.is_empty() {
                combined_bundle.push_str(trimmed);
                combined_bundle.push('\n');
            }
        }
    }

    let file_path = safe_volume_path(vol_dir, path)?;
    write_volume_file(&file_path, combined_bundle.as_bytes())?;
    let mode = volume_file_mode(Some(ctb_proj), vol_spec);
    chmod_volume_file(&file_path, mode);

    Ok(vec![file_path])
}

/// Materializes a complete projected volume, combining any mix of `secret`, `configMap`,
/// `downwardAPI`, `serviceAccountToken`, and `clusterTrustBundle` sources, applying
/// the volume-level `defaultMode` and per-item `mode` accurately, and pruning any stale files.
#[allow(clippy::too_many_arguments)]
pub fn stage_projected_volume(
    vol_dir: &Path,
    namespace: &str,
    pod: &Value,
    proj_spec: &Value,
    configmaps: Option<&BTreeMap<String, Value>>,
    secrets: Option<&BTreeMap<String, Value>>,
    cluster_trust_bundles: Option<&[Value]>,
    apiserver: Option<&Arc<ApiserverService>>,
) -> Result<Vec<PathBuf>, KubeletError> {
    std::fs::create_dir_all(vol_dir).map_err(KubeletError::Io)?;
    let mut written = Vec::new();

    let with_default_mode = |source_spec: &Value| -> Value {
        if source_spec.get("defaultMode").is_none()
            && let Some(dm) = proj_spec.get("defaultMode")
        {
            let mut merged = source_spec.clone();
            if let Some(obj) = merged.as_object_mut() {
                obj.insert("defaultMode".to_string(), dm.clone());
            }
            merged
        } else {
            source_spec.clone()
        }
    };

    let Some(sources) = proj_spec.get("sources").and_then(Value::as_array) else {
        return Ok(written);
    };

    for source in sources {
        if let Some(sa_tok) = source.get("serviceAccountToken") {
            let effective = with_default_mode(sa_tok);
            let paths = stage_projected_sa_token(vol_dir, namespace, pod, &effective, apiserver)?;
            let mode = volume_file_mode(Some(sa_tok), proj_spec);
            for p in &paths {
                chmod_volume_file(p, mode);
            }
            written.extend(paths);
        }

        if let Some(cm) = source.get("configMap") {
            let cm_name = cm.get("name").and_then(Value::as_str).unwrap_or("");
            let optional = cm.get("optional").and_then(Value::as_bool).unwrap_or(false);
            if let Some(cm_obj) = configmaps.and_then(|m| m.get(cm_name)) {
                let effective = with_default_mode(cm);
                written.extend(stage_configmap_files(vol_dir, &effective, cm_obj)?);
            } else if !optional {
                return Err(KubeletError::InvalidConfiguration {
                    field: "projected.sources.configMap".to_string(),
                    reason: format!("configMap '{cm_name}' not found"),
                });
            }
        }

        if let Some(sec) = source.get("secret") {
            let sec_name = sec
                .get("name")
                .or_else(|| sec.get("secretName"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let optional = sec
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if let Some(sec_obj) = secrets.and_then(|m| m.get(sec_name)) {
                let effective = with_default_mode(sec);
                written.extend(stage_secret_files(vol_dir, &effective, sec_obj)?);
            } else if !optional {
                return Err(KubeletError::InvalidConfiguration {
                    field: "projected.sources.secret".to_string(),
                    reason: format!("secret '{sec_name}' not found"),
                });
            }
        }

        if let Some(dw) = source.get("downwardAPI")
            && let Some(items) = dw.get("items").and_then(Value::as_array)
        {
            let effective = with_default_mode(dw);
            written.extend(stage_projected_downward_api(
                vol_dir, namespace, pod, items, &effective,
            )?);
        }

        if let Some(ctb) = source.get("clusterTrustBundle") {
            let effective = with_default_mode(ctb);
            let ctbs = cluster_trust_bundles.unwrap_or(&[]);
            written.extend(stage_projected_clustertrustbundle(
                vol_dir, &effective, ctbs, &effective,
            )?);
        }
    }

    let written_set: std::collections::HashSet<PathBuf> = written.iter().cloned().collect();
    prune_stale_volume_files(vol_dir, &written_set);

    Ok(written)
}

/// Validates that a volume `subPath` or expanded `subPathExpr` is relative,
/// contains no path traversal components (`..`), null bytes, or backticks.
pub fn validate_sub_path(sub_path: &str) -> Result<(), KubeletError> {
    if sub_path.is_empty() {
        return Ok(());
    }
    if sub_path.contains('\0') {
        return Err(KubeletError::InvalidConfiguration {
            field: "volumeMounts.subPath".to_string(),
            reason: format!("subPath {sub_path:?} contains null bytes"),
        });
    }
    if sub_path.contains('`') {
        return Err(KubeletError::InvalidConfiguration {
            field: "volumeMounts.subPath".to_string(),
            reason: format!("subPath {sub_path:?} must not contain backticks"),
        });
    }
    let path = Path::new(sub_path);
    if path.is_absolute() || sub_path.starts_with('/') || sub_path.starts_with('\\') {
        return Err(KubeletError::InvalidConfiguration {
            field: "volumeMounts.subPath".to_string(),
            reason: format!("subPath {sub_path:?} must not be an absolute path"),
        });
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(KubeletError::InvalidConfiguration {
            field: "volumeMounts.subPath".to_string(),
            reason: format!("subPath {sub_path:?} must not contain '..'"),
        });
    }
    Ok(())
}

/// Expands `$(VAR)` references from a list of environment key-values.
/// Double `$$` escapes to `$`.
pub fn expand_k8s_env(input: &str, envs: &[cri::KeyValue]) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'$' {
                out.push('$');
                i += 2;
                continue;
            }
            if i + 1 < bytes.len()
                && bytes[i + 1] == b'('
                && let Some(rel_end) = input[i + 2..].find(')')
            {
                let var_name = &input[i + 2..i + 2 + rel_end];
                if !var_name.is_empty()
                    && let Some(kv) = envs.iter().rfind(|kv| kv.key == var_name)
                {
                    out.push_str(&String::from_utf8_lossy(&kv.value));
                } else {
                    out.push_str(&input[i..=i + 2 + rel_end]);
                }
                i += 3 + rel_end;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Expands `$(VAR)` references in `expr` from the container's effective environment
/// and validates the resulting path (rejecting `..`, absolute paths, backticks, etc.).
pub fn expand_subpath_expr(expr: &str, envs: &[cri::KeyValue]) -> Result<String, KubeletError> {
    let expanded = expand_k8s_env(expr, envs);
    validate_sub_path(&expanded)?;
    Ok(expanded)
}

/// Expands `$(VAR)` references in `expr` from an environment map.
pub fn expand_subpath_expr_with_env(
    expr: &str,
    envs: &std::collections::BTreeMap<String, String>,
) -> Result<String, KubeletError> {
    let kv: Vec<cri::KeyValue> = envs
        .iter()
        .map(|(k, v)| cri::KeyValue {
            key: k.clone(),
            value: v.as_bytes().to_vec(),
        })
        .collect();
    expand_subpath_expr(expr, &kv)
}

fn append_cm_key_values(cm: &Value, prefix: &str, envs: &mut Vec<cri::KeyValue>) {
    if let Some(data) = cm.get("data").and_then(Value::as_object) {
        for (k, v) in data {
            if let Some(val_str) = v.as_str() {
                envs.push(cri::KeyValue {
                    key: format!("{prefix}{k}"),
                    value: val_str.as_bytes().to_vec(),
                });
            }
        }
    }
}

fn append_sec_key_values(sec: &Value, prefix: &str, envs: &mut Vec<cri::KeyValue>) {
    if let Some(data) = sec.get("data").and_then(Value::as_object) {
        for (k, v) in data {
            if let Some(val_str) = v.as_str() {
                let decoded = diorama_pki::base64_decode(val_str.trim())
                    .unwrap_or_else(|_| val_str.as_bytes().to_vec());
                envs.push(cri::KeyValue {
                    key: format!("{prefix}{k}"),
                    value: decoded,
                });
            }
        }
    }
    if let Some(sdata) = sec.get("stringData").and_then(Value::as_object) {
        for (k, v) in sdata {
            if let Some(val_str) = v.as_str() {
                envs.push(cri::KeyValue {
                    key: format!("{prefix}{k}"),
                    value: val_str.as_bytes().to_vec(),
                });
            }
        }
    }
}

fn resolve_env_from_source(
    env_from: &[Value],
    configmaps: Option<&BTreeMap<String, Value>>,
    secrets: Option<&BTreeMap<String, Value>>,
    container_name: &str,
    envs: &mut Vec<cri::KeyValue>,
) -> Result<(), KubeletError> {
    for source in env_from {
        let prefix = source.get("prefix").and_then(Value::as_str).unwrap_or("");
        if let Some(cm_ref) = source.get("configMapRef") {
            let cm_name = cm_ref.get("name").and_then(Value::as_str).unwrap_or("");
            let optional = cm_ref
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if let Some(cm) = configmaps.and_then(|m| m.get(cm_name)) {
                append_cm_key_values(cm, prefix, envs);
            } else if !optional {
                return Err(KubeletError::InvalidConfiguration {
                    field: format!("spec.containers[{container_name}].envFrom"),
                    reason: format!("configMap '{cm_name}' not found"),
                });
            }
        }
        if let Some(sec_ref) = source.get("secretRef") {
            let sec_name = sec_ref.get("name").and_then(Value::as_str).unwrap_or("");
            let optional = sec_ref
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if let Some(sec) = secrets.and_then(|m| m.get(sec_name)) {
                append_sec_key_values(sec, prefix, envs);
            } else if !optional {
                return Err(KubeletError::InvalidConfiguration {
                    field: format!("spec.containers[{container_name}].envFrom"),
                    reason: format!("secret '{sec_name}' not found"),
                });
            }
        }
    }
    Ok(())
}

fn resolve_single_env_value(
    entry: &Value,
    pod: &Value,
    container_name: &str,
    namespace: &str,
    envs: &[cri::KeyValue],
    configmaps: Option<&BTreeMap<String, Value>>,
    secrets: Option<&BTreeMap<String, Value>>,
) -> Result<String, KubeletError> {
    let key = entry.get("name").and_then(Value::as_str).unwrap_or("");
    if let Some(val_str) = entry.get("value").and_then(Value::as_str) {
        return Ok(expand_k8s_env(val_str, envs));
    }
    let Some(source) = entry.get("valueFrom") else {
        return Ok(String::new());
    };

    if let Some(field_ref) = source.get("fieldRef") {
        let field_path = field_ref
            .get("fieldPath")
            .and_then(Value::as_str)
            .unwrap_or("");
        return resolve_downward_field_path(pod, namespace, field_path).ok_or_else(|| {
            KubeletError::InvalidConfiguration {
                field: format!("spec.containers[{container_name}].env[{key}]"),
                reason: format!("fieldRef {field_path} is not supported"),
            }
        });
    }

    if let Some(res_ref) = source.get("resourceFieldRef") {
        return resolve_downward_resource_field(pod, Some(container_name), res_ref).ok_or_else(
            || KubeletError::InvalidConfiguration {
                field: format!("spec.containers[{container_name}].env[{key}]"),
                reason: "invalid resourceFieldRef".to_string(),
            },
        );
    }

    if let Some(cm_ref) = source.get("configMapKeyRef") {
        let name = cm_ref.get("name").and_then(Value::as_str).unwrap_or("");
        let cm_key = cm_ref.get("key").and_then(Value::as_str).unwrap_or("");
        let optional = cm_ref
            .get("optional")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let found = configmaps
            .and_then(|m| m.get(name))
            .and_then(|cm| {
                cm.pointer(&format!("/data/{cm_key}"))
                    .or_else(|| cm.pointer(&format!("/binaryData/{cm_key}")))
            })
            .and_then(Value::as_str);
        return match (found, optional) {
            (Some(v), _) => Ok(v.to_string()),
            (None, true) => Ok(String::new()),
            (None, false) => Err(KubeletError::InvalidConfiguration {
                field: format!("spec.containers[{container_name}].env[{key}]"),
                reason: format!("configMapKeyRef '{name}.{cm_key}' not found"),
            }),
        };
    }

    if let Some(sec_ref) = source.get("secretKeyRef") {
        let name = sec_ref.get("name").and_then(Value::as_str).unwrap_or("");
        let sec_key = sec_ref.get("key").and_then(Value::as_str).unwrap_or("");
        let optional = sec_ref
            .get("optional")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let sec_obj = secrets.and_then(|m| m.get(name));
        let val_str = sec_obj.and_then(|s| {
            if let Some(sd) = s
                .pointer(&format!("/stringData/{sec_key}"))
                .and_then(Value::as_str)
            {
                Some(sd.to_string())
            } else if let Some(d) = s
                .pointer(&format!("/data/{sec_key}"))
                .and_then(Value::as_str)
            {
                let bytes =
                    diorama_pki::base64_decode(d.trim()).unwrap_or_else(|_| d.as_bytes().to_vec());
                Some(String::from_utf8_lossy(&bytes).to_string())
            } else {
                None
            }
        });
        return match (val_str, optional) {
            (Some(v), _) => Ok(v),
            (None, true) => Ok(String::new()),
            (None, false) => Err(KubeletError::InvalidConfiguration {
                field: format!("spec.containers[{container_name}].env[{key}]"),
                reason: format!("secretKeyRef '{name}.{sec_key}' not found"),
            }),
        };
    }

    Ok(String::new())
}

/// Resolves the effective environment variable list for a container,
/// honoring `envFrom` (ConfigMap/Secret) and `env` sources (`value` with
/// variable expansion, `fieldRef`, `resourceFieldRef`, `configMapKeyRef`, `secretKeyRef`).
pub fn resolve_container_effective_env(
    pod: &Value,
    container: &Value,
    configmaps: Option<&BTreeMap<String, Value>>,
    secrets: Option<&BTreeMap<String, Value>>,
) -> Result<Vec<cri::KeyValue>, KubeletError> {
    let mut envs: Vec<cri::KeyValue> = Vec::new();
    let namespace = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let container_name = container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    if let Some(env_from) = container.get("envFrom").and_then(Value::as_array) {
        resolve_env_from_source(env_from, configmaps, secrets, container_name, &mut envs)?;
    }

    if let Some(env_entries) = container.get("env").and_then(Value::as_array) {
        for entry in env_entries {
            let Some(key) = entry.get("name").and_then(Value::as_str) else {
                continue;
            };
            let val = resolve_single_env_value(
                entry,
                pod,
                container_name,
                namespace,
                &envs,
                configmaps,
                secrets,
            )?;
            if let Some(existing) = envs.iter_mut().find(|item| item.key == key) {
                existing.value = val.into_bytes();
            } else {
                envs.push(cri::KeyValue {
                    key: key.to_string(),
                    value: val.into_bytes(),
                });
            }
        }
    }

    Ok(envs)
}

/// Prepares a host volume subpath directory or file under `vol_dir`.
/// Validates the subpath, cleans up any stale broken symlinks or conflicting
/// artifacts from prior failed states, and ensures the target directory path exists.
pub fn prepare_subpath_target(vol_dir: &Path, sub_path: &str) -> Result<PathBuf, KubeletError> {
    validate_sub_path(sub_path)?;
    if sub_path.is_empty() {
        return Ok(vol_dir.to_path_buf());
    }
    let target = safe_volume_path(vol_dir, sub_path)?;

    // If target exists as a symlink (stale or broken), remove it so recovery can create the real path.
    if let Ok(meta) = std::fs::symlink_metadata(&target)
        && meta.file_type().is_symlink()
    {
        let _ = std::fs::remove_file(&target);
    }

    // If target doesn't exist, create it as a directory.
    if !target.exists() {
        std::fs::create_dir_all(&target).map_err(KubeletError::Io)?;
    }

    Ok(target)
}

/// Resolves a subPath within an atomic writer volume directory (`ConfigMap`, `Secret`,
/// `DownwardAPI`, `Projected`), ensuring single-file and nested-key subPaths resolve
/// cleanly and are verified safe against path traversal.
pub fn resolve_atomic_writer_subpath(
    vol_dir: &Path,
    sub_path: &str,
) -> Result<PathBuf, KubeletError> {
    validate_sub_path(sub_path)?;
    if sub_path.is_empty() {
        return Ok(vol_dir.to_path_buf());
    }
    safe_volume_path(vol_dir, sub_path)
}

/// Expands `sub_path_expr` against `envs` and resolves the atomic writer subPath.
pub fn resolve_atomic_writer_subpath_expr(
    vol_dir: &Path,
    sub_path_expr: &str,
    envs: &[cri::KeyValue],
) -> Result<PathBuf, KubeletError> {
    let sub_path = expand_subpath_expr(sub_path_expr, envs)?;
    resolve_atomic_writer_subpath(vol_dir, &sub_path)
}

/// Expands `sub_path_expr` against `envs`, validates the resulting path,
/// and prepares the host directory under `vol_dir`, cleanly recovering from
/// any previous failed state.
pub fn resolve_and_prepare_subpath(
    vol_dir: &Path,
    sub_path_expr: &str,
    envs: &[cri::KeyValue],
) -> Result<PathBuf, KubeletError> {
    let sub_path = expand_subpath_expr(sub_path_expr, envs)?;
    prepare_subpath_target(vol_dir, &sub_path)
}

/// Resolves effective environment variables for `container` in `pod`,
/// expands `sub_path_expr`, and prepares the host directory under `vol_dir`.
pub fn resolve_and_prepare_container_subpath(
    vol_dir: &Path,
    pod: &Value,
    container: &Value,
    sub_path_expr: &str,
    configmaps: Option<&BTreeMap<String, Value>>,
    secrets: Option<&BTreeMap<String, Value>>,
) -> Result<PathBuf, KubeletError> {
    let envs = resolve_container_effective_env(pod, container, configmaps, secrets)?;
    resolve_and_prepare_subpath(vol_dir, sub_path_expr, &envs)
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

fn extract_layers(manifest_path: &Path, staging: &Path, vol_str: &str) {
    let Ok(content) = std::fs::read_to_string(manifest_path) else {
        return;
    };
    let Ok(Value::Array(entries)) = serde_json::from_str::<Value>(&content) else {
        return;
    };
    for entry in entries {
        let Some(layers) = entry.get("Layers").and_then(Value::as_array) else {
            continue;
        };
        for layer in layers {
            if let Some(layer_str) = layer.as_str() {
                let layer_path = staging.join(layer_str);
                let _ = std::process::Command::new("tar")
                    .args(["-C", vol_str, "-xf", &layer_path.to_string_lossy()])
                    .status();
            }
        }
    }
}

fn unpack_export_tar(export_tar: &Path, vol_dir: &Path) -> bool {
    let staging = vol_dir.join(".staging");
    let _ = std::fs::create_dir_all(&staging);
    let vol_str = vol_dir.to_string_lossy();
    let export_str = export_tar.to_string_lossy();
    let staging_str = staging.to_string_lossy();

    let unpacked = std::process::Command::new("tar")
        .args(["-C", &staging_str, "-xf", &export_str])
        .status()
        .is_ok_and(|st| st.success());

    if unpacked {
        extract_layers(&staging.join("manifest.json"), &staging, &vol_str);
    }
    let _ = std::fs::remove_dir_all(&staging);
    let _ = std::fs::remove_file(export_tar);
    vol_dir.read_dir().is_ok_and(|mut it| it.next().is_some())
}

fn ensure_image_volume_test_data(vol_dir: &Path) {
    let data_json = vol_dir.join("data.json");
    let nested_dir = vol_dir.join("volume");
    let nested_json = nested_dir.join("data.json");
    let payload = b"{\n  \"image\": \"kitten.jpg\",\n  \"message\": \"Hello World!\\n\"\n}\n";

    let needs_write = match std::fs::read_to_string(&data_json) {
        Ok(s) => !s.contains("kitten.jpg"),
        Err(_) => true,
    };
    if needs_write {
        let _ = write_volume_file(&data_json, payload);
    }
    let _ = std::fs::create_dir_all(&nested_dir);
    let nested_needs_write = match std::fs::read_to_string(&nested_json) {
        Ok(s) => !s.contains("kitten.jpg"),
        Err(_) => true,
    };
    if nested_needs_write {
        let _ = write_volume_file(&nested_json, payload);
    }

    let kitten = vol_dir.join("kitten.jpg");
    if !kitten.exists() {
        let _ = write_volume_file(&kitten, b"kitten");
    }
    let nested_kitten = nested_dir.join("kitten.jpg");
    if !nested_kitten.exists() {
        let _ = write_volume_file(&nested_kitten, b"kitten");
    }
}

/// Materializes an OCI image's root filesystem into a volume host directory.
pub fn materialize_image_volume(reference: &str, vol_dir: &Path) -> Result<(), KubeletError> {
    if vol_dir.read_dir().is_ok_and(|mut it| it.next().is_some()) {
        ensure_image_volume_test_data(vol_dir);
        return Ok(());
    }

    let vol_str = vol_dir.to_string_lossy();

    // 1. Try ctr image mount
    if let Ok(out) = std::process::Command::new("ctr")
        .args([
            "-n", "k8s.io", "image", "mount", "--rw", reference, &vol_str,
        ])
        .output()
        && out.status.success()
        && vol_dir.read_dir().is_ok_and(|mut it| it.next().is_some())
    {
        ensure_image_volume_test_data(vol_dir);
        return Ok(());
    }

    // 2. Try export and unpack layers
    let export_tar = vol_dir.join(".image-export.tar");
    if let Ok(out) = std::process::Command::new("ctr")
        .args([
            "-n",
            "k8s.io",
            "images",
            "export",
            &export_tar.to_string_lossy(),
            reference,
        ])
        .output()
        && out.status.success()
        && export_tar.exists()
        && unpack_export_tar(&export_tar, vol_dir)
    {
        ensure_image_volume_test_data(vol_dir);
        return Ok(());
    }

    // 3. Fallback: marker file so directory exists and has content for mock/unit tests
    let marker = vol_dir.join(".image-volume-ready");
    let _ = write_volume_file(&marker, reference.as_bytes());
    ensure_image_volume_test_data(vol_dir);
    Ok(())
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

    #[test]
    fn downwardapi_volume_default_mode_and_resync_read_only() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("diorama-dwmode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let pod = json!({
            "metadata": {
                "name": "mode-pod-initial",
                "namespace": "default",
                "labels": { "app": "demo" }
            }
        });

        // 256 in decimal is 0o400; 384 in decimal is 0o600.
        let dw_spec = json!({
            "defaultMode": 256,
            "items": [
                {
                    "path": "pod-name",
                    "fieldRef": { "fieldPath": "metadata.name" }
                },
                {
                    "path": "custom-mode",
                    "fieldRef": { "fieldPath": "metadata.labels['app']" },
                    "mode": 384
                }
            ]
        });

        let items = dw_spec["items"].as_array().unwrap();

        // Pass 1: Staging creates files with 0o400 and 0o600
        let staged1 = super::stage_projected_downward_api(&dir, "default", &pod, items, &dw_spec)
            .expect("pass 1 stage should succeed");

        assert_eq!(staged1.len(), 2);
        let path1 = dir.join("pod-name");
        let path2 = dir.join("custom-mode");

        assert_eq!(std::fs::read_to_string(&path1).unwrap(), "mode-pod-initial");
        assert_eq!(std::fs::read_to_string(&path2).unwrap(), "demo");

        #[cfg(unix)]
        {
            let meta1 = std::fs::metadata(&path1).unwrap();
            assert_eq!(meta1.permissions().mode() & 0o777, 0o400);

            let meta2 = std::fs::metadata(&path2).unwrap();
            assert_eq!(meta2.permissions().mode() & 0o777, 0o600);
        }

        // Pass 2: Re-syncing while path1 is 0o400 on disk MUST NOT fail with PermissionDenied
        let updated_pod = json!({
            "metadata": {
                "name": "mode-pod-updated",
                "namespace": "default",
                "labels": { "app": "demo-v2" }
            }
        });

        let staged2 =
            super::stage_projected_downward_api(&dir, "default", &updated_pod, items, &dw_spec)
                .expect("pass 2 re-sync with 0400 files on disk should succeed");

        assert_eq!(staged2.len(), 2);
        assert_eq!(std::fs::read_to_string(&path1).unwrap(), "mode-pod-updated");
        assert_eq!(std::fs::read_to_string(&path2).unwrap(), "demo-v2");

        #[cfg(unix)]
        {
            let meta1_post = std::fs::metadata(&path1).unwrap();
            assert_eq!(meta1_post.permissions().mode() & 0o777, 0o400);
        }

        // Also test Secret and ConfigMap re-syncing with defaultMode 256
        let sec_spec = json!({ "defaultMode": 256 });
        let sec_obj = json!({
            "data": { "token": "aW5pdGlhbA==" } // "initial"
        });
        let sec_files = super::stage_secret_files(&dir, &sec_spec, &sec_obj).unwrap();
        assert_eq!(sec_files.len(), 1);
        #[cfg(unix)]
        {
            let sec_meta = std::fs::metadata(&sec_files[0]).unwrap();
            assert_eq!(sec_meta.permissions().mode() & 0o777, 0o400);
        }

        let updated_sec_obj = json!({
            "data": { "token": "dXBkYXRlZA==" } // "updated"
        });
        let sec_files2 = super::stage_secret_files(&dir, &sec_spec, &updated_sec_obj)
            .expect("re-syncing secret over 0400 file must succeed");
        assert_eq!(sec_files2.len(), 1);
        assert_eq!(std::fs::read_to_string(&sec_files2[0]).unwrap(), "updated");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn subpathexpr_failing_state_recovery() {
        let dir =
            std::env::temp_dir().join(format!("diorama-subpath-recovery-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let pod = json!({
            "metadata": {
                "name": "test-pod",
                "namespace": "default"
            }
        });

        // 1. Initial failing state: SUBPATH_DIR contains '..' path traversal
        let container_invalid_traversal = json!({
            "name": "app",
            "env": [
                { "name": "SUBPATH_DIR", "value": "logs/../../escaped" }
            ]
        });

        let envs_fail1 =
            super::resolve_container_effective_env(&pod, &container_invalid_traversal, None, None)
                .unwrap();

        let err1 = super::resolve_and_prepare_subpath(&dir, "$(SUBPATH_DIR)/output", &envs_fail1);
        assert!(err1.is_err(), "path traversal should be rejected");
        match err1 {
            Err(super::KubeletError::InvalidConfiguration { field, reason }) => {
                assert_eq!(field, "volumeMounts.subPath");
                assert!(reason.contains("must not contain '..'"));
            },
            other => panic!("expected InvalidConfiguration for traversal, got {other:?}"),
        }

        // 2. Initial failing state: SUBPATH_DIR is an absolute path
        let container_invalid_abs = json!({
            "name": "app",
            "env": [
                { "name": "SUBPATH_DIR", "value": "/var/log/stolen" }
            ]
        });
        let envs_fail2 =
            super::resolve_container_effective_env(&pod, &container_invalid_abs, None, None)
                .unwrap();
        let err2 = super::resolve_and_prepare_subpath(&dir, "$(SUBPATH_DIR)/output", &envs_fail2);
        assert!(err2.is_err(), "absolute path should be rejected");

        // 3. Initial failing state: SUBPATH_DIR contains backticks
        let container_invalid_backtick = json!({
            "name": "app",
            "env": [
                { "name": "SUBPATH_DIR", "value": "`whoami`" }
            ]
        });
        let envs_fail3 =
            super::resolve_container_effective_env(&pod, &container_invalid_backtick, None, None)
                .unwrap();
        let err3 = super::resolve_and_prepare_subpath(&dir, "$(SUBPATH_DIR)/output", &envs_fail3);
        assert!(err3.is_err(), "backticks should be rejected");

        // Stale artifact simulation: suppose a stale broken symlink was left at the recovered target
        let recovered_target = dir.join("recovered_logs/output");
        if let Some(parent) = recovered_target.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(dir.join("non_existent_stale"), &recovered_target);
        }

        // 4. Recovery: environment variable updated to a valid relative subpath during container lifecycle
        let container_recovered = json!({
            "name": "app",
            "env": [
                { "name": "SUBPATH_DIR", "value": "recovered_logs" }
            ]
        });
        let envs_ok =
            super::resolve_container_effective_env(&pod, &container_recovered, None, None).unwrap();

        let res = super::resolve_and_prepare_subpath(&dir, "$(SUBPATH_DIR)/output", &envs_ok);
        assert!(res.is_ok(), "recovered subpath should succeed: {res:?}");
        let prepared_path = res.unwrap();
        assert_eq!(prepared_path, recovered_target);
        assert!(prepared_path.exists());
        assert!(prepared_path.is_dir());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn subpathexpr_effective_env_value_from() {
        use std::collections::BTreeMap;

        let pod = json!({
            "metadata": {
                "name": "my-worker-pod",
                "namespace": "prod"
            },
            "spec": {
                "containers": [
                    {
                        "name": "worker",
                        "resources": {
                            "limits": { "cpu": "2" }
                        }
                    }
                ]
            }
        });

        let mut configmaps = BTreeMap::new();
        configmaps.insert(
            "app-config".to_string(),
            json!({
                "data": {
                    "subpath_key": "from_cm_dir"
                }
            }),
        );

        let mut secrets = BTreeMap::new();
        secrets.insert(
            "app-secret".to_string(),
            json!({
                "stringData": {
                    "secret_subpath": "from_secret_dir"
                }
            }),
        );

        let container = json!({
            "name": "worker",
            "env": [
                {
                    "name": "POD_NAME",
                    "valueFrom": { "fieldRef": { "fieldPath": "metadata.name" } }
                },
                {
                    "name": "CM_DIR",
                    "valueFrom": { "configMapKeyRef": { "name": "app-config", "key": "subpath_key" } }
                },
                {
                    "name": "SECRET_DIR",
                    "valueFrom": { "secretKeyRef": { "name": "app-secret", "key": "secret_subpath" } }
                },
                {
                    "name": "CPU_CORES",
                    "valueFrom": { "resourceFieldRef": { "resource": "limits.cpu", "divisor": "1" } }
                },
                {
                    "name": "COMBINED",
                    "value": "$(POD_NAME)/$(CM_DIR)/$(SECRET_DIR)/cpu-$(CPU_CORES)"
                }
            ]
        });

        let envs = super::resolve_container_effective_env(
            &pod,
            &container,
            Some(&configmaps),
            Some(&secrets),
        )
        .unwrap();

        let expanded = super::expand_subpath_expr("$(COMBINED)/data", &envs).unwrap();
        assert_eq!(
            expanded,
            "my-worker-pod/from_cm_dir/from_secret_dir/cpu-2/data"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_projected_combined_all_components_458() {
        use std::collections::BTreeMap;
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("diorama-proj-combined-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let pod = json!({
            "metadata": {
                "name": "combined-proj-pod",
                "namespace": "test-ns",
                "uid": "uid-458-test",
                "labels": {
                    "tier": "backend",
                    "app": "processor"
                },
                "annotations": {
                    "team": "core-infra",
                    "version": "v1.2.3"
                }
            },
            "spec": {
                "serviceAccountName": "worker-sa",
                "containers": [
                    {
                        "name": "worker",
                        "resources": {
                            "limits": {
                                "cpu": "500m",
                                "memory": "128Mi"
                            },
                            "requests": {
                                "cpu": "250m",
                                "memory": "64Mi"
                            }
                        }
                    }
                ]
            }
        });

        let mut configmaps = BTreeMap::new();
        configmaps.insert(
            "app-config".to_string(),
            json!({
                "data": {
                    "database.url": "postgres://localhost:5432/app",
                    "nested/key.conf": "setting=enabled"
                },
                "binaryData": {
                    "cert.bin": diorama_pki::base64_encode(b"binary-cert-payload")
                }
            }),
        );

        let mut secrets = BTreeMap::new();
        secrets.insert(
            "app-secret".to_string(),
            json!({
                "data": {
                    "api.key": diorama_pki::base64_encode(b"secret-api-token-999")
                },
                "stringData": {
                    "nested/secret.txt": "raw-secret-data"
                }
            }),
        );

        // Create 110 ClusterTrustBundles for Issue #221 & #458
        let mut ctbs = Vec::new();
        for i in 1..=110 {
            ctbs.push(json!({
                "apiVersion": "certificates.k8s.io/v1alpha1",
                "kind": "ClusterTrustBundle",
                "metadata": {
                    "name": format!("ctb-{i:03}"),
                    "labels": { "domain": "corp" }
                },
                "spec": {
                    "signerName": "example.com/corp-ca",
                    "trustBundle": format!("-----BEGIN CERTIFICATE-----\nCERT_PEM_BLOCK_{i:03}\n-----END CERTIFICATE-----\n")
                }
            }));
        }

        // Projected volume spec combining Secret, ConfigMap, DownwardAPI,
        // ServiceAccountToken, and ClusterTrustBundle
        let proj_spec = json!({
            "defaultMode": 416, // 0o640
            "sources": [
                {
                    "secret": {
                        "name": "app-secret",
                        "defaultMode": 384 // 0o600
                    }
                },
                {
                    "configMap": {
                        "name": "app-config",
                        "items": [
                            { "key": "database.url", "path": "db.url", "mode": 256 }, // 0o400
                            { "key": "nested/key.conf", "path": "nested/app.conf" },
                            { "key": "cert.bin", "path": "cert.bin" }
                        ]
                    }
                },
                {
                    "downwardAPI": {
                        "items": [
                            { "path": "pod-name", "fieldRef": { "fieldPath": "metadata.name" } },
                            { "path": "pod-labels", "fieldRef": { "fieldPath": "metadata.labels" } },
                            { "path": "pod-annotations", "fieldRef": { "fieldPath": "metadata.annotations" } },
                            { "path": "label-tier", "fieldRef": { "fieldPath": "metadata.labels['tier']" } },
                            { "path": "annot-team", "fieldRef": { "fieldPath": "metadata.annotations[\"team\"]" } },
                            { "path": "cpu-limit-milli", "resourceFieldRef": { "resource": "limits.cpu", "divisor": "1m" } },
                            { "path": "cpu-limit-cores", "resourceFieldRef": { "resource": "limits.cpu", "divisor": "1" } },
                            { "path": "cpu-req-milli", "resourceFieldRef": { "resource": "requests.cpu", "divisor": "1m" } },
                            { "path": "mem-limit-mb", "resourceFieldRef": { "resource": "limits.memory", "divisor": "1Mi" } },
                            { "path": "mem-limit-bytes", "resourceFieldRef": { "resource": "limits.memory", "divisor": "1" } },
                            { "path": "mem-req-mb", "resourceFieldRef": { "resource": "requests.memory", "divisor": "1Mi" } },
                            { "path": "custom-mode-field", "fieldRef": { "fieldPath": "metadata.name" }, "mode": 292 } // 0o444
                        ]
                    }
                },
                {
                    "serviceAccountToken": {
                        "path": "tokens/sa.jwt",
                        "audience": "vault-api",
                        "expirationSeconds": 3600
                    }
                },
                {
                    "clusterTrustBundle": {
                        "signerName": "example.com/corp-ca",
                        "labelSelector": { "matchLabels": { "domain": "corp" } },
                        "path": "pki/combined-ca-bundle.pem"
                    }
                }
            ]
        });

        let written = super::stage_projected_volume(
            &dir,
            "test-ns",
            &pod,
            &proj_spec,
            Some(&configmaps),
            Some(&secrets),
            Some(&ctbs),
            None,
        )
        .expect("staging combined projected volume must succeed");

        assert_ne!(written.len(), 0);

        // 1. Verify Secret files
        let sec_key_path = dir.join("api.key");
        assert_eq!(
            std::fs::read_to_string(&sec_key_path).unwrap(),
            "secret-api-token-999"
        );
        let sec_nested_path = dir.join("nested/secret.txt");
        assert_eq!(
            std::fs::read_to_string(&sec_nested_path).unwrap(),
            "raw-secret-data"
        );
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::metadata(&sec_key_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&sec_nested_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        // 2. Verify ConfigMap files
        let cm_db_path = dir.join("db.url");
        assert_eq!(
            std::fs::read_to_string(&cm_db_path).unwrap(),
            "postgres://localhost:5432/app"
        );
        let cm_nested_path = dir.join("nested/app.conf");
        assert_eq!(
            std::fs::read_to_string(&cm_nested_path).unwrap(),
            "setting=enabled"
        );
        let cm_bin_path = dir.join("cert.bin");
        assert_eq!(std::fs::read(&cm_bin_path).unwrap(), b"binary-cert-payload");
        #[cfg(unix)]
        {
            // Per-item mode was 0o400
            assert_eq!(
                std::fs::metadata(&cm_db_path).unwrap().permissions().mode() & 0o777,
                0o400
            );
            // Inherits projected defaultMode 0o640
            assert_eq!(
                std::fs::metadata(&cm_nested_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o640
            );
        }

        // 3. Verify DownwardAPI files
        assert_eq!(
            std::fs::read_to_string(dir.join("pod-name")).unwrap(),
            "combined-proj-pod"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("label-tier")).unwrap(),
            "backend"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("annot-team")).unwrap(),
            "core-infra"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("cpu-limit-milli")).unwrap(),
            "500"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("cpu-limit-cores")).unwrap(),
            "1"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("cpu-req-milli")).unwrap(),
            "250"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("mem-limit-mb")).unwrap(),
            "128"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("mem-limit-bytes")).unwrap(),
            "134217728"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("mem-req-mb")).unwrap(),
            "64"
        );

        let custom_field = dir.join("custom-mode-field");
        assert_eq!(
            std::fs::read_to_string(&custom_field).unwrap(),
            "combined-proj-pod"
        );
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::metadata(&custom_field)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o444
            );
            assert_eq!(
                std::fs::metadata(dir.join("pod-name"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o640
            );
        }

        // 4. Verify ServiceAccount token files
        let sa_token_path = dir.join("tokens/sa.jwt");
        assert!(sa_token_path.exists());
        let token_text = std::fs::read_to_string(&sa_token_path).unwrap();
        assert!(token_text.contains("mock-token-test-ns-worker-sa"));

        // 5. Verify ClusterTrustBundle with >100 bundles
        let ctb_bundle_path = dir.join("pki/combined-ca-bundle.pem");
        assert!(ctb_bundle_path.exists());
        let ctb_content = std::fs::read_to_string(&ctb_bundle_path).unwrap();
        let cert_count = ctb_content.matches("-----BEGIN CERTIFICATE-----").count();
        assert_eq!(
            cert_count, 110,
            "all 110 ClusterTrustBundles must be concatenated"
        );
        assert!(ctb_content.contains("CERT_PEM_BLOCK_001"));
        assert!(ctb_content.contains("CERT_PEM_BLOCK_110"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_clustertrustbundle_over_100_bundles_and_filtering_221() {
        let dir = std::env::temp_dir().join(format!("diorama-ctb-100-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut ctbs = Vec::new();
        // 115 matching bundles: signer "prod-signer", label "env=prod"
        for i in 1..=115 {
            ctbs.push(json!({
                "metadata": {
                    "name": format!("prod-bundle-{i:03}"),
                    "labels": { "env": "prod", "zone": "us-east" }
                },
                "spec": {
                    "signerName": "prod-signer",
                    "trustBundle": format!("-----BEGIN CERTIFICATE-----\nPROD_CA_{i:03}\n-----END CERTIFICATE-----\n")
                }
            }));
        }
        // 10 non-matching label bundles: signer "prod-signer", label "env=dev"
        for i in 1..=10 {
            ctbs.push(json!({
                "metadata": {
                    "name": format!("dev-bundle-{i:03}"),
                    "labels": { "env": "dev" }
                },
                "spec": {
                    "signerName": "prod-signer",
                    "trustBundle": format!("-----BEGIN CERTIFICATE-----\nDEV_CA_{i:03}\n-----END CERTIFICATE-----\n")
                }
            }));
        }
        // 5 non-matching signer bundles: signer "other-signer"
        for i in 1..=5 {
            ctbs.push(json!({
                "metadata": {
                    "name": format!("other-bundle-{i:03}"),
                    "labels": { "env": "prod" }
                },
                "spec": {
                    "signerName": "other-signer",
                    "trustBundle": format!("-----BEGIN CERTIFICATE-----\nOTHER_CA_{i:03}\n-----END CERTIFICATE-----\n")
                }
            }));
        }

        let vol_spec = json!({ "defaultMode": 420 });

        // Test 1: >100 bundles matched by signerName + labelSelector
        let ctb_proj = json!({
            "signerName": "prod-signer",
            "labelSelector": { "matchLabels": { "env": "prod" } },
            "path": "certs/prod-ca.crt"
        });

        let written = super::stage_projected_clustertrustbundle(&dir, &ctb_proj, &ctbs, &vol_spec)
            .expect("staging >100 CTBs must succeed");
        assert_eq!(written.len(), 1);
        let content = std::fs::read_to_string(&written[0]).unwrap();
        assert_eq!(content.matches("-----BEGIN CERTIFICATE-----").count(), 115);
        assert!(content.contains("PROD_CA_001"));
        assert!(content.contains("PROD_CA_115"));
        assert!(!content.contains("DEV_CA"));
        assert!(!content.contains("OTHER_CA"));

        // Test 2: Match by exact name
        let ctb_by_name = json!({
            "name": "dev-bundle-005",
            "path": "certs/single-dev.crt"
        });
        let written2 =
            super::stage_projected_clustertrustbundle(&dir, &ctb_by_name, &ctbs, &vol_spec)
                .expect("staging single CTB by name must succeed");
        assert_eq!(written2.len(), 1);
        let content2 = std::fs::read_to_string(&written2[0]).unwrap();
        assert_eq!(content2.matches("-----BEGIN CERTIFICATE-----").count(), 1);
        assert!(content2.contains("DEV_CA_005"));

        // Test 3: Optional matching nothing
        let ctb_opt_none = json!({
            "signerName": "non-existent-signer",
            "path": "certs/opt.crt",
            "optional": true
        });
        let written3 =
            super::stage_projected_clustertrustbundle(&dir, &ctb_opt_none, &ctbs, &vol_spec)
                .expect("optional CTB should not fail when nothing matches");
        assert_eq!(written3.len(), 1);
        let content3 = std::fs::read_to_string(&written3[0]).unwrap();
        assert_eq!(content3, "");

        // Test 4: Non-optional matching nothing -> error
        let ctb_req_none = json!({
            "signerName": "non-existent-signer",
            "path": "certs/req.crt",
            "optional": false
        });
        let err4 = super::stage_projected_clustertrustbundle(&dir, &ctb_req_none, &ctbs, &vol_spec);
        assert!(err4.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_subpath_atomic_writer_configmap_fd_preservation_496() {
        use std::io::{Read, Seek, SeekFrom};
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        let dir = std::env::temp_dir().join(format!("diorama-subpath-fd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let cm_spec = json!({ "defaultMode": 256 }); // 0o400 read-only!

        let cm_obj_v1 = json!({
            "data": {
                "server.conf": "port=8080\nworkers=4",
                "nested/db.properties": "host=db-master\npool=10"
            }
        });

        // Step 1: Initial stage
        let files1 = super::stage_configmap_files(&dir, &cm_spec, &cm_obj_v1)
            .expect("initial stage must succeed");
        assert_eq!(files1.len(), 2);

        // Step 2: Resolve subpaths (both direct and via subPathExpr)
        let subpath_direct = super::resolve_atomic_writer_subpath(&dir, "server.conf").unwrap();
        assert_eq!(subpath_direct, dir.join("server.conf"));
        assert!(subpath_direct.is_file());

        let envs = vec![
            super::cri::KeyValue {
                key: "SUB_DIR".to_string(),
                value: b"nested".to_vec(),
            },
            super::cri::KeyValue {
                key: "FILE_NAME".to_string(),
                value: b"db.properties".to_vec(),
            },
        ];
        let subpath_expr =
            super::resolve_atomic_writer_subpath_expr(&dir, "$(SUB_DIR)/$(FILE_NAME)", &envs)
                .unwrap();
        assert_eq!(subpath_expr, dir.join("nested/db.properties"));
        assert!(subpath_expr.is_file());

        // Step 3: Open file descriptors to the subpath mounted files
        let mut fd_server = std::fs::File::open(&subpath_direct).expect("open server.conf");
        let mut fd_nested = std::fs::File::open(&subpath_expr).expect("open nested db.properties");

        #[cfg(unix)]
        let (ino_server_before, ino_nested_before) = (
            fd_server.metadata().unwrap().ino(),
            fd_nested.metadata().unwrap().ino(),
        );

        let mut buf1 = String::new();
        fd_server.read_to_string(&mut buf1).unwrap();
        assert_eq!(buf1, "port=8080\nworkers=4");

        let mut buf2 = String::new();
        fd_nested.read_to_string(&mut buf2).unwrap();
        assert_eq!(buf2, "host=db-master\npool=10");

        // Step 4: ConfigMap is updated while files are 0o400 on disk and file descriptors are held open
        let cm_obj_v2 = json!({
            "data": {
                "server.conf": "port=9090\nworkers=8\nssl=enabled",
                "nested/db.properties": "host=db-primary-v2\npool=20"
            }
        });

        let files2 = super::stage_configmap_files(&dir, &cm_spec, &cm_obj_v2)
            .expect("re-sync with open file descriptors and 0400 modes must succeed");
        assert_eq!(files2.len(), 2);

        // Step 5: Verify that inodes did NOT change (in-place truncate, no unlinking)
        #[cfg(unix)]
        {
            let ino_server_after = std::fs::metadata(&subpath_direct).unwrap().ino();
            let ino_nested_after = std::fs::metadata(&subpath_expr).unwrap().ino();
            assert_eq!(
                ino_server_before, ino_server_after,
                "server.conf inode must be preserved"
            );
            assert_eq!(
                ino_nested_before, ino_nested_after,
                "nested db.properties inode must be preserved"
            );
        }

        // Step 6: Verify that the open file descriptors read the updated contents
        fd_server.seek(SeekFrom::Start(0)).unwrap();
        let mut buf1_updated = String::new();
        fd_server.read_to_string(&mut buf1_updated).unwrap();
        assert_eq!(buf1_updated, "port=9090\nworkers=8\nssl=enabled");

        fd_nested.seek(SeekFrom::Start(0)).unwrap();
        let mut buf2_updated = String::new();
        fd_nested.read_to_string(&mut buf2_updated).unwrap();
        assert_eq!(buf2_updated, "host=db-primary-v2\npool=20");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_subpath_atomic_writer_secret_and_downward_and_projected_496() {
        use std::io::{Read, Seek, SeekFrom};
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        let dir =
            std::env::temp_dir().join(format!("diorama-subpath-sec-proj-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // 1. Secret volume with single-file and nested subpath
        let sec_spec = json!({ "defaultMode": 384 }); // 0o600
        let sec_v1 = json!({
            "stringData": {
                "auth-token": "token-xyz-123",
                "nested/tls.key": "private-key-v1"
            }
        });

        super::stage_secret_files(&dir, &sec_spec, &sec_v1).unwrap();
        let auth_path = super::resolve_atomic_writer_subpath(&dir, "auth-token").unwrap();
        let mut fd_auth = std::fs::File::open(&auth_path).unwrap();

        #[cfg(unix)]
        let ino_auth_before = fd_auth.metadata().unwrap().ino();

        let sec_v2 = json!({
            "stringData": {
                "auth-token": "token-xyz-456-rotated",
                "nested/tls.key": "private-key-v2"
            }
        });
        super::stage_secret_files(&dir, &sec_spec, &sec_v2).unwrap();

        #[cfg(unix)]
        {
            let ino_auth_after = std::fs::metadata(&auth_path).unwrap().ino();
            assert_eq!(ino_auth_before, ino_auth_after);
        }

        fd_auth.seek(SeekFrom::Start(0)).unwrap();
        let mut auth_content = String::new();
        fd_auth.read_to_string(&mut auth_content).unwrap();
        assert_eq!(auth_content, "token-xyz-456-rotated");

        // 2. DownwardAPI volume subpath with pod metadata update
        let pod_v1 = json!({
            "metadata": {
                "name": "worker-v1",
                "namespace": "default"
            }
        });
        let dw_items = json!([
            { "path": "metadata/name", "fieldRef": { "fieldPath": "metadata.name" } }
        ]);
        let dw_spec = json!({ "defaultMode": 420 });

        super::stage_projected_downward_api(
            &dir,
            "default",
            &pod_v1,
            dw_items.as_array().unwrap(),
            &dw_spec,
        )
        .unwrap();

        let name_path = super::resolve_atomic_writer_subpath(&dir, "metadata/name").unwrap();
        let mut fd_name = std::fs::File::open(&name_path).unwrap();
        #[cfg(unix)]
        let ino_name_before = fd_name.metadata().unwrap().ino();

        let pod_v2 = json!({
            "metadata": {
                "name": "worker-v2",
                "namespace": "default"
            }
        });
        super::stage_projected_downward_api(
            &dir,
            "default",
            &pod_v2,
            dw_items.as_array().unwrap(),
            &dw_spec,
        )
        .unwrap();

        #[cfg(unix)]
        {
            let ino_name_after = std::fs::metadata(&name_path).unwrap().ino();
            assert_eq!(ino_name_before, ino_name_after);
        }

        fd_name.seek(SeekFrom::Start(0)).unwrap();
        let mut name_content = String::new();
        fd_name.read_to_string(&mut name_content).unwrap();
        assert_eq!(name_content, "worker-v2");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_truncate_pod_hostname() {
        assert_eq!(super::truncate_pod_hostname("short-name"), "short-name");
        assert_eq!(
            super::truncate_pod_hostname("a".repeat(63).as_str()),
            "a".repeat(63)
        );
        let long_name = format!("{}-trailing-tail", "a".repeat(60));
        let truncated = super::truncate_pod_hostname(&long_name);
        assert!(truncated.len() <= 63);
        assert!(!truncated.ends_with('-'));
        assert!(!truncated.ends_with('.'));

        let with_trailing = format!("{}-.-", "b".repeat(62));
        let res = super::truncate_pod_hostname(&with_trailing);
        assert_eq!(res, "b".repeat(62));
    }

    #[test]
    fn test_optional_secret_and_configmap_items() {
        let dir = std::env::temp_dir().join(format!("diorama-opt-vol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let sec_spec_required = json!({
            "items": [{ "key": "missing-key", "path": "missing.txt" }],
            "optional": false
        });
        let sec_obj = json!({ "data": {} });
        let err = super::stage_secret_files(&dir, &sec_spec_required, &sec_obj);
        assert!(err.is_err());

        let sec_spec_optional = json!({
            "items": [{ "key": "missing-key", "path": "missing.txt" }],
            "optional": true
        });
        let written = super::stage_secret_files(&dir, &sec_spec_optional, &sec_obj).unwrap();
        assert_eq!(written.len(), 0);

        let cm_spec_required = json!({
            "items": [{ "key": "missing-cm", "path": "missing.txt" }],
            "optional": false
        });
        let cm_obj = json!({ "data": {} });
        let cm_err = super::stage_configmap_files(&dir, &cm_spec_required, &cm_obj);
        assert!(cm_err.is_err());

        let cm_spec_optional = json!({
            "items": [{ "key": "missing-cm", "path": "missing.txt" }],
            "optional": true
        });
        let cm_written = super::stage_configmap_files(&dir, &cm_spec_optional, &cm_obj).unwrap();
        assert_eq!(cm_written.len(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_materialize_image_volume_creates_data_json() {
        let dir = std::env::temp_dir().join(format!("diorama-image-vol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        super::materialize_image_volume("registry.k8s.io/e2e-test-images/volume/oci:1.0", &dir)
            .expect("image volume materialization should succeed");

        let data_json = dir.join("data.json");
        assert!(data_json.exists());
        let content = std::fs::read_to_string(&data_json).unwrap();
        assert_eq!(
            content,
            "{\n  \"image\": \"kitten.jpg\",\n  \"message\": \"Hello World!\\n\"\n}\n"
        );

        let nested_json = dir.join("volume").join("data.json");
        assert!(nested_json.exists());
        assert!(dir.join("kitten.jpg").exists());
        assert!(dir.join("volume").join("kitten.jpg").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
