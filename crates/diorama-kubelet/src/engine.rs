//! Container-engine adapter: implements the CRI-shaped [`RuntimeProvider`] over
//! engines that manage pods and containers from a command line (podman today;
//! docker or nerdctl would be further engines).
//!
//! CRI sandboxes map onto engine pods, so containers of one Pod share the pod's
//! network and IPC namespaces and the sandbox reports the pod's own IP.
//! Engines own only their command-line spelling; this module owns the mapping
//! between CRI messages and engine summaries. Volume mounts, ports and resource
//! limits are not yet translated.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::KubeletError;
use crate::workload::{
    ANNOTATION_RESTART_COUNT, ExecResult, LABEL_CONTAINER_NAME, LABEL_POD_NAME,
    LABEL_POD_NAMESPACE, LABEL_POD_UID, LogOptions, RuntimeProvider, cri, nanos_from_secs,
};

/// Engine label recording the sandbox attempt, which CRI carries in metadata.
pub const LABEL_SANDBOX_ATTEMPT: &str = "io.diorama.sandbox.attempt";
/// Engine label mirroring the CRI restart-count annotation.
pub const LABEL_RESTART_COUNT: &str = ANNOTATION_RESTART_COUNT;
const STOP_TIMEOUT_SECS: i64 = 5;

/// Volume mount for a container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountSpec {
    pub container_path: String,
    pub host_path: String,
    pub readonly: bool,
}

/// Resource constraints for a container.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceSpec {
    pub cpu_shares: Option<i64>,
    pub cpu_quota: Option<i64>,
    pub cpu_period: Option<i64>,
    pub cpuset_cpus: Option<String>,
    pub memory_limit_in_bytes: Option<i64>,
}

/// Port mapping for a pod sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortMappingSpec {
    pub host_ip: Option<String>,
    pub host_port: i32,
    pub container_port: i32,
    pub protocol: String,
}

impl PortMappingSpec {
    #[must_use]
    pub fn to_argument(&self) -> String {
        let proto = if self.protocol.is_empty() {
            "tcp"
        } else {
            &self.protocol
        };
        let host_prefix = self
            .host_ip
            .as_deref()
            .filter(|ip| !ip.is_empty())
            .map(|ip| format!("{ip}:"))
            .unwrap_or_default();
        if self.host_port > 0 {
            format!(
                "{host_prefix}{}:{}/{proto}",
                self.host_port, self.container_port
            )
        } else {
            format!("{host_prefix}{}/{proto}", self.container_port)
        }
    }
}

impl From<&cri::PortMapping> for PortMappingSpec {
    fn from(pm: &cri::PortMapping) -> Self {
        let protocol = match cri::Protocol::try_from(pm.protocol) {
            Ok(cri::Protocol::Udp) => "udp".to_string(),
            Ok(cri::Protocol::Sctp) => "sctp".to_string(),
            _ => "tcp".to_string(),
        };
        Self {
            host_ip: if pm.host_ip.is_empty() {
                None
            } else {
                Some(pm.host_ip.clone())
            },
            host_port: pm.host_port,
            container_port: pm.container_port,
            protocol,
        }
    }
}

/// Engine-neutral description of one container to create inside a pod.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    /// Engine pod to join; the CRI sandbox.
    pub pod: Option<String>,
    /// Replaces the image entrypoint (CRI `command`).
    pub entrypoint: Option<Vec<String>>,
    /// Replaces the image command (CRI `args`).
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub working_dir: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub mounts: Vec<MountSpec>,
    pub resources: Option<ResourceSpec>,
}

/// Normalised container state as reported by an engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContainerState {
    /// Created, paused or otherwise not executing; carries the engine's own word.
    Idle(String),
    Running {
        started_at: Option<u64>,
    },
    Exited {
        exit_code: i32,
        started_at: Option<u64>,
        finished_at: Option<u64>,
    },
}

/// One container known to the engine. Timestamps are Unix seconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerSummary {
    pub id: String,
    pub name: String,
    /// Engine pod the container belongs to, if any.
    pub pod_id: String,
    pub image: String,
    /// Image identity, preferably `sha256:<digest>` or `repo@sha256:<digest>`.
    pub image_id: String,
    pub labels: BTreeMap<String, String>,
    pub state: ContainerState,
    pub created: Option<u64>,
}

/// One engine pod. `running` is true while the pod's infrastructure is up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PodSummary {
    pub id: String,
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub running: bool,
    pub created: Option<u64>,
}

/// Pod- and container-level operations of a container engine.
#[async_trait]
pub trait ContainerEngine: std::fmt::Debug + Send + Sync {
    /// Short engine name used as the `containerID` scheme, e.g. `podman`.
    fn name(&self) -> &str;

    /// Engine version if known, reported in the node's `containerRuntimeVersion`.
    fn version(&self) -> Option<String>;

    /// Verifies the engine answers.
    async fn ping(&self) -> Result<(), KubeletError>;

    /// Creates a pod (sandbox) with labels and returns its id. The pod is not started.
    async fn pod_create(
        &self,
        name: &str,
        labels: &BTreeMap<String, String>,
        ports: &[PortMappingSpec],
    ) -> Result<String, KubeletError>;
    async fn pod_start(&self, id: &str) -> Result<(), KubeletError>;
    async fn pod_stop(&self, id: &str, timeout_secs: i64) -> Result<(), KubeletError>;
    async fn pod_remove(&self, id: &str) -> Result<(), KubeletError>;
    /// Lists pods carrying every given label.
    async fn pod_list(
        &self,
        label_filters: &[(&str, &str)],
    ) -> Result<Vec<PodSummary>, KubeletError>;
    /// The pod's network address, if it has one.
    async fn pod_ip(&self, id: &str) -> Result<Option<String>, KubeletError>;

    /// Creates a container from an image the engine already has; returns its id.
    async fn container_create(&self, spec: &ContainerSpec) -> Result<String, KubeletError>;
    async fn container_start(&self, id: &str) -> Result<(), KubeletError>;
    /// Stops a container: TERM, then KILL after `timeout_secs`.
    async fn container_stop(&self, id: &str, timeout_secs: i64) -> Result<(), KubeletError>;
    async fn container_remove(&self, id: &str) -> Result<(), KubeletError>;
    /// Lists containers, including stopped ones, carrying every label and, if given, in the pod.
    async fn container_list(
        &self,
        label_filters: &[(&str, &str)],
        pod: Option<&str>,
    ) -> Result<Vec<ContainerSummary>, KubeletError>;
    async fn container_inspect(&self, id: &str) -> Result<ContainerSummary, KubeletError>;

    /// Image identity if the engine has the image.
    async fn image_id(&self, image: &str) -> Result<Option<String>, KubeletError>;
    /// Pulls an image and returns its identity.
    async fn image_pull(&self, image: &str) -> Result<String, KubeletError>;

    /// Captured stdout and stderr of a container, interleaved in time order.
    async fn logs(&self, id: &str, options: &LogOptions) -> Result<String, KubeletError>;
    /// Runs a command inside a running container.
    async fn exec(&self, id: &str, command: &[String]) -> Result<ExecResult, KubeletError>;
}

/// [`RuntimeProvider`] over any [`ContainerEngine`].
#[derive(Clone, Debug)]
pub struct EngineRuntimeAdapter {
    engine: Arc<dyn ContainerEngine>,
}

impl EngineRuntimeAdapter {
    #[must_use]
    pub fn new(engine: Arc<dyn ContainerEngine>) -> Self {
        Self { engine }
    }

    #[must_use]
    pub fn engine(&self) -> &Arc<dyn ContainerEngine> {
        &self.engine
    }
}

fn label_filters(selector: &BTreeMap<String, String>) -> Vec<(&str, &str)> {
    selector
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

fn label_u32(labels: &BTreeMap<String, String>, key: &str) -> u32 {
    labels.get(key).and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn nanos(secs: Option<u64>) -> i64 {
    secs.map_or(0, nanos_from_secs)
}

/// Pod name the kubelet gives an engine pod, as upstream shims did.
#[must_use]
pub fn sandbox_name(metadata: &cri::PodSandboxMetadata) -> String {
    format!(
        "k8s_POD_{}_{}_{}_{}",
        metadata.name, metadata.namespace, metadata.uid, metadata.attempt
    )
}

/// Container name the kubelet gives an engine container.
#[must_use]
pub fn container_name(
    container: &cri::ContainerMetadata,
    sandbox: &cri::PodSandboxMetadata,
) -> String {
    format!(
        "k8s_{}_{}_{}_{}_{}",
        container.name, sandbox.name, sandbox.namespace, sandbox.uid, container.attempt
    )
}

/// Translates a CRI container configuration into an engine spec.
#[must_use]
pub fn container_spec(
    pod_id: &str,
    config: &cri::ContainerConfig,
    sandbox: &cri::PodSandboxConfig,
) -> ContainerSpec {
    let default_meta = cri::ContainerMetadata::default();
    let default_sandbox = cri::PodSandboxMetadata::default();
    let meta = config.metadata.as_ref().unwrap_or(&default_meta);
    let sandbox_meta = sandbox.metadata.as_ref().unwrap_or(&default_sandbox);
    let mut labels = config.labels.clone();
    labels.insert(LABEL_RESTART_COUNT.to_string(), meta.attempt.to_string());
    let mounts = config
        .mounts
        .iter()
        .map(|m| MountSpec {
            container_path: m.container_path.clone(),
            host_path: m.host_path.clone(),
            readonly: m.readonly,
        })
        .collect();
    let resources = config
        .linux
        .as_ref()
        .and_then(|l| l.resources.as_ref())
        .and_then(|r| {
            let spec = ResourceSpec {
                cpu_shares: (r.cpu_shares > 0).then_some(r.cpu_shares),
                cpu_quota: (r.cpu_quota > 0).then_some(r.cpu_quota),
                cpu_period: (r.cpu_period > 0).then_some(r.cpu_period),
                cpuset_cpus: (!r.cpuset_cpus.is_empty()).then(|| r.cpuset_cpus.clone()),
                memory_limit_in_bytes: (r.memory_limit_in_bytes > 0)
                    .then_some(r.memory_limit_in_bytes),
            };
            if spec.cpu_shares.is_none()
                && spec.cpu_quota.is_none()
                && spec.cpu_period.is_none()
                && spec.cpuset_cpus.is_none()
                && spec.memory_limit_in_bytes.is_none()
            {
                None
            } else {
                Some(spec)
            }
        });
    ContainerSpec {
        name: container_name(meta, sandbox_meta),
        image: config
            .image
            .as_ref()
            .map(|i| i.image.clone())
            .unwrap_or_default(),
        pod: Some(pod_id.to_string()),
        entrypoint: (!config.command.is_empty()).then(|| config.command.clone()),
        args: config.args.clone(),
        env: config
            .envs
            .iter()
            .map(|kv| {
                (
                    kv.key.clone(),
                    String::from_utf8_lossy(&kv.value).into_owned(),
                )
            })
            .collect(),
        working_dir: (!config.working_dir.is_empty()).then(|| config.working_dir.clone()),
        labels,
        mounts,
        resources,
    }
}

fn sandbox_from_summary(pod: &PodSummary) -> cri::PodSandbox {
    cri::PodSandbox {
        id: pod.id.clone(),
        metadata: Some(cri::PodSandboxMetadata {
            name: pod.labels.get(LABEL_POD_NAME).cloned().unwrap_or_default(),
            uid: pod.labels.get(LABEL_POD_UID).cloned().unwrap_or_default(),
            namespace: pod
                .labels
                .get(LABEL_POD_NAMESPACE)
                .cloned()
                .unwrap_or_default(),
            attempt: label_u32(&pod.labels, LABEL_SANDBOX_ATTEMPT),
        }),
        state: if pod.running {
            cri::PodSandboxState::SandboxReady as i32
        } else {
            cri::PodSandboxState::SandboxNotready as i32
        },
        created_at: nanos(pod.created),
        labels: pod.labels.clone(),
        annotations: BTreeMap::new(),
        runtime_handler: String::new(),
    }
}

fn cri_state(state: &ContainerState) -> cri::ContainerState {
    match state {
        ContainerState::Idle(word) if word == "created" || word == "configured" => {
            cri::ContainerState::ContainerCreated
        },
        ContainerState::Idle(_) => cri::ContainerState::ContainerUnknown,
        ContainerState::Running { .. } => cri::ContainerState::ContainerRunning,
        ContainerState::Exited { .. } => cri::ContainerState::ContainerExited,
    }
}

fn container_from_summary(summary: &ContainerSummary) -> cri::Container {
    cri::Container {
        id: summary.id.clone(),
        pod_sandbox_id: summary.pod_id.clone(),
        metadata: Some(cri::ContainerMetadata {
            name: summary
                .labels
                .get(LABEL_CONTAINER_NAME)
                .cloned()
                .unwrap_or_default(),
            attempt: label_u32(&summary.labels, LABEL_RESTART_COUNT),
        }),
        image: Some(cri::ImageSpec {
            image: summary.image.clone(),
            ..cri::ImageSpec::default()
        }),
        image_ref: summary.image_id.clone(),
        state: cri_state(&summary.state) as i32,
        created_at: nanos(summary.created),
        labels: summary.labels.clone(),
        annotations: BTreeMap::from([(
            ANNOTATION_RESTART_COUNT.to_string(),
            label_u32(&summary.labels, LABEL_RESTART_COUNT).to_string(),
        )]),
        image_id: summary.image_id.clone(),
    }
}

fn status_from_summary(summary: &ContainerSummary) -> cri::ContainerStatus {
    let listed = container_from_summary(summary);
    let (started_at, finished_at, exit_code) = match &summary.state {
        ContainerState::Running { started_at } => (nanos(*started_at), 0, 0),
        ContainerState::Exited {
            exit_code,
            started_at,
            finished_at,
        } => (nanos(*started_at), nanos(*finished_at), *exit_code),
        ContainerState::Idle(_) => (0, 0, 0),
    };
    cri::ContainerStatus {
        id: listed.id,
        metadata: listed.metadata,
        state: listed.state,
        created_at: listed.created_at,
        started_at,
        finished_at,
        exit_code,
        image: listed.image,
        image_ref: listed.image_ref,
        reason: String::new(),
        message: String::new(),
        labels: listed.labels,
        annotations: listed.annotations,
        mounts: Vec::new(),
        log_path: String::new(),
        resources: None,
        image_id: listed.image_id,
        user: None,
        stop_signal: 0,
    }
}

#[async_trait]
impl RuntimeProvider for EngineRuntimeAdapter {
    fn provider_name(&self) -> &str {
        self.engine.name()
    }

    fn is_external(&self) -> bool {
        true
    }

    fn runtime_version(&self) -> String {
        self.engine
            .version()
            .unwrap_or_else(|| "unknown".to_string())
    }

    async fn check_available(&self) -> Result<(), KubeletError> {
        self.engine.ping().await
    }

    async fn run_pod_sandbox(
        &self,
        config: &cri::PodSandboxConfig,
    ) -> Result<String, KubeletError> {
        let default_meta = cri::PodSandboxMetadata::default();
        let meta = config.metadata.as_ref().unwrap_or(&default_meta);
        let mut labels = config.labels.clone();
        labels.insert(LABEL_SANDBOX_ATTEMPT.to_string(), meta.attempt.to_string());
        let ports: Vec<PortMappingSpec> = config
            .port_mappings
            .iter()
            .map(PortMappingSpec::from)
            .collect();
        let id = self
            .engine
            .pod_create(&sandbox_name(meta), &labels, &ports)
            .await?;
        if let Err(e) = self.engine.pod_start(&id).await {
            let _ = self.engine.pod_remove(&id).await;
            return Err(e);
        }
        Ok(id)
    }

    async fn stop_pod_sandbox(&self, pod_sandbox_id: &str) -> Result<(), KubeletError> {
        self.engine
            .pod_stop(pod_sandbox_id, STOP_TIMEOUT_SECS)
            .await
    }

    async fn remove_pod_sandbox(&self, pod_sandbox_id: &str) -> Result<(), KubeletError> {
        self.engine.pod_remove(pod_sandbox_id).await
    }

    async fn list_pod_sandbox(
        &self,
        filter: Option<&cri::PodSandboxFilter>,
    ) -> Result<Vec<cri::PodSandbox>, KubeletError> {
        let empty = BTreeMap::new();
        let selector = filter.map_or(&empty, |f| &f.label_selector);
        let wanted_state = filter.and_then(|f| f.state.as_ref()).map(|s| s.state);
        let wanted_id = filter.map(|f| f.id.as_str()).filter(|id| !id.is_empty());
        Ok(self
            .engine
            .pod_list(&label_filters(selector))
            .await?
            .iter()
            .map(sandbox_from_summary)
            .filter(|s| wanted_state.is_none_or(|state| state == s.state))
            .filter(|s| wanted_id.is_none_or(|id| id == s.id))
            .collect())
    }

    async fn pod_sandbox_status(
        &self,
        pod_sandbox_id: &str,
    ) -> Result<cri::PodSandboxStatus, KubeletError> {
        let pods = self.engine.pod_list(&[]).await?;
        let pod = pods
            .iter()
            .find(|p| p.id == pod_sandbox_id || p.id.starts_with(pod_sandbox_id))
            .ok_or_else(|| KubeletError::ContainerOperationFailed {
                container: pod_sandbox_id.to_string(),
                reason: "sandbox not found".to_string(),
            })?;
        let sandbox = sandbox_from_summary(pod);
        let ip = if pod.running {
            self.engine.pod_ip(&pod.id).await.ok().flatten()
        } else {
            None
        };
        Ok(cri::PodSandboxStatus {
            id: sandbox.id,
            metadata: sandbox.metadata,
            state: sandbox.state,
            created_at: sandbox.created_at,
            network: ip.map(|ip| cri::PodSandboxNetworkStatus {
                ip,
                additional_ips: Vec::new(),
            }),
            linux: None,
            labels: sandbox.labels,
            annotations: sandbox.annotations,
            runtime_handler: String::new(),
        })
    }

    async fn create_container(
        &self,
        pod_sandbox_id: &str,
        config: &cri::ContainerConfig,
        sandbox_config: &cri::PodSandboxConfig,
    ) -> Result<String, KubeletError> {
        let spec = container_spec(pod_sandbox_id, config, sandbox_config);
        self.engine.container_create(&spec).await
    }

    async fn start_container(&self, container_id: &str) -> Result<(), KubeletError> {
        self.engine.container_start(container_id).await
    }

    async fn stop_container(
        &self,
        container_id: &str,
        timeout_secs: i64,
    ) -> Result<(), KubeletError> {
        self.engine.container_stop(container_id, timeout_secs).await
    }

    async fn remove_container(&self, container_id: &str) -> Result<(), KubeletError> {
        self.engine.container_remove(container_id).await
    }

    async fn list_containers(
        &self,
        filter: Option<&cri::ContainerFilter>,
    ) -> Result<Vec<cri::Container>, KubeletError> {
        let empty = BTreeMap::new();
        let selector = filter.map_or(&empty, |f| &f.label_selector);
        let pod = filter
            .map(|f| f.pod_sandbox_id.as_str())
            .filter(|id| !id.is_empty());
        let wanted_state = filter.and_then(|f| f.state.as_ref()).map(|s| s.state);
        let wanted_id = filter.map(|f| f.id.as_str()).filter(|id| !id.is_empty());
        Ok(self
            .engine
            .container_list(&label_filters(selector), pod)
            .await?
            .iter()
            .map(container_from_summary)
            .filter(|c| wanted_state.is_none_or(|state| state == c.state))
            .filter(|c| wanted_id.is_none_or(|id| id == c.id))
            .collect())
    }

    async fn container_status(
        &self,
        container_id: &str,
    ) -> Result<cri::ContainerStatus, KubeletError> {
        let summary = self.engine.container_inspect(container_id).await?;
        Ok(status_from_summary(&summary))
    }

    async fn exec_sync(
        &self,
        container_id: &str,
        cmd: &[String],
        timeout_secs: i64,
    ) -> Result<ExecResult, KubeletError> {
        if timeout_secs > 0 {
            let dur = std::time::Duration::from_secs(timeout_secs.cast_unsigned());
            tokio::time::timeout(dur, self.engine.exec(container_id, cmd))
                .await
                .map_err(|_| KubeletError::ContainerOperationFailed {
                    container: container_id.to_string(),
                    reason: format!("exec timed out after {timeout_secs}s"),
                })?
        } else {
            self.engine.exec(container_id, cmd).await
        }
    }

    async fn container_logs(
        &self,
        container_id: &str,
        options: &LogOptions,
    ) -> Result<String, KubeletError> {
        self.engine.logs(container_id, options).await
    }

    async fn image_status(
        &self,
        image: &cri::ImageSpec,
    ) -> Result<Option<cri::Image>, KubeletError> {
        Ok(self
            .engine
            .image_id(&image.image)
            .await?
            .map(|id| cri::Image {
                id,
                repo_tags: vec![image.image.clone()],
                spec: Some(image.clone()),
                ..cri::Image::default()
            }))
    }

    async fn pull_image(
        &self,
        image: &cri::ImageSpec,
        _sandbox_config: Option<&cri::PodSandboxConfig>,
    ) -> Result<String, KubeletError> {
        self.engine.image_pull(&image.image).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn sandbox_config() -> cri::PodSandboxConfig {
        cri::PodSandboxConfig {
            metadata: Some(cri::PodSandboxMetadata {
                name: "hello".to_string(),
                uid: "uid-1".to_string(),
                namespace: "default".to_string(),
                attempt: 0,
            }),
            labels: crate::workload::sandbox_labels("default", "hello", "uid-1"),
            ..cri::PodSandboxConfig::default()
        }
    }

    fn container_config(attempt: u32) -> cri::ContainerConfig {
        cri::ContainerConfig {
            metadata: Some(cri::ContainerMetadata {
                name: "hello".to_string(),
                attempt,
            }),
            image: Some(cri::ImageSpec {
                image: "localhost/diorama-hello:latest".to_string(),
                ..cri::ImageSpec::default()
            }),
            command: vec!["/diorama-hello".to_string()],
            args: vec!["600".to_string()],
            working_dir: "/work".to_string(),
            envs: vec![cri::KeyValue {
                key: "GREETING".to_string(),
                value: b"hi".to_vec(),
            }],
            labels: crate::workload::container_labels("default", "hello", "uid-1", "hello"),
            ..cri::ContainerConfig::default()
        }
    }

    #[test]
    fn container_spec_maps_cri_config_onto_the_engine() {
        let spec = container_spec("pod1", &container_config(2), &sandbox_config());
        assert_eq!(spec.name, "k8s_hello_hello_default_uid-1_2");
        assert_eq!(spec.pod.as_deref(), Some("pod1"));
        assert_eq!(spec.image, "localhost/diorama-hello:latest");
        assert_eq!(
            spec.entrypoint.as_deref(),
            Some(&["/diorama-hello".to_string()][..])
        );
        assert_eq!(spec.args, ["600"]);
        assert_eq!(spec.env, [("GREETING".to_string(), "hi".to_string())]);
        assert_eq!(spec.working_dir.as_deref(), Some("/work"));
        assert_eq!(spec.labels[LABEL_RESTART_COUNT], "2");
        assert_eq!(spec.labels[LABEL_POD_UID], "uid-1");
        assert_eq!(
            sandbox_name(sandbox_config().metadata.as_ref().unwrap()),
            "k8s_POD_hello_default_uid-1_0"
        );

        let mut cfg = container_config(2);
        cfg.mounts.push(cri::Mount {
            container_path: "/mnt/data".to_string(),
            host_path: "/var/lib/data".to_string(),
            readonly: true,
            ..cri::Mount::default()
        });
        cfg.linux = Some(cri::LinuxContainerConfig {
            resources: Some(cri::LinuxContainerResources {
                cpu_shares: 512,
                cpu_quota: 25_000,
                cpu_period: 100_000,
                cpuset_cpus: "0-1".to_string(),
                memory_limit_in_bytes: 104_857_600,
                ..cri::LinuxContainerResources::default()
            }),
            ..cri::LinuxContainerConfig::default()
        });
        let spec_with_res = container_spec("pod1", &cfg, &sandbox_config());
        assert_eq!(spec_with_res.mounts.len(), 1);
        assert_eq!(spec_with_res.mounts[0].container_path, "/mnt/data");
        assert_eq!(spec_with_res.mounts[0].host_path, "/var/lib/data");
        assert!(spec_with_res.mounts[0].readonly);
        let res = spec_with_res.resources.as_ref().unwrap();
        assert_eq!(res.cpu_shares, Some(512));
        assert_eq!(res.cpu_quota, Some(25_000));
        assert_eq!(res.cpu_period, Some(100_000));
        assert_eq!(res.cpuset_cpus.as_deref(), Some("0-1"));
        assert_eq!(res.memory_limit_in_bytes, Some(104_857_600));
    }

    #[test]
    fn summaries_map_onto_cri_states_and_nanoseconds() {
        let mut summary = ContainerSummary {
            id: "abc".to_string(),
            name: "k8s_hello_hello_default_uid-1_1".to_string(),
            pod_id: "pod1".to_string(),
            image: "img".to_string(),
            image_id: "sha256:abc".to_string(),
            labels: {
                let mut labels =
                    crate::workload::container_labels("default", "hello", "uid-1", "hello");
                labels.insert(LABEL_RESTART_COUNT.to_string(), "1".to_string());
                labels
            },
            state: ContainerState::Exited {
                exit_code: 3,
                started_at: Some(10),
                finished_at: Some(15),
            },
            created: Some(9),
        };
        let status = status_from_summary(&summary);
        assert_eq!(status.state, cri::ContainerState::ContainerExited as i32);
        assert_eq!(status.exit_code, 3);
        assert_eq!(status.started_at, 10_000_000_000);
        assert_eq!(status.finished_at, 15_000_000_000);
        assert_eq!(status.created_at, 9_000_000_000);
        assert_eq!(status.metadata.as_ref().unwrap().attempt, 1);
        assert_eq!(status.metadata.as_ref().unwrap().name, "hello");
        summary.state = ContainerState::Idle("created".to_string());
        assert_eq!(
            status_from_summary(&summary).state,
            cri::ContainerState::ContainerCreated as i32
        );
        summary.state = ContainerState::Idle("paused".to_string());
        assert_eq!(
            status_from_summary(&summary).state,
            cri::ContainerState::ContainerUnknown as i32
        );
        let pod = PodSummary {
            id: "pod1".to_string(),
            name: "k8s_POD_hello_default_uid-1_0".to_string(),
            labels: {
                let mut labels = crate::workload::sandbox_labels("default", "hello", "uid-1");
                labels.insert(LABEL_SANDBOX_ATTEMPT.to_string(), "0".to_string());
                labels
            },
            running: true,
            created: None,
        };
        let sandbox = sandbox_from_summary(&pod);
        assert_eq!(sandbox.state, cri::PodSandboxState::SandboxReady as i32);
        assert_eq!(sandbox.metadata.as_ref().unwrap().uid, "uid-1");
    }

    /// In-memory engine with pods.
    #[derive(Debug, Default)]
    struct FakeEngine {
        pods: Mutex<Vec<PodSummary>>,
        containers: Mutex<Vec<ContainerSummary>>,
        next: std::sync::atomic::AtomicUsize,
        images: Mutex<Vec<String>>,
        stops: Mutex<Vec<(String, i64)>>,
    }

    impl FakeEngine {
        fn id(&self, kind: &str) -> String {
            format!(
                "{kind}{}",
                self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
            )
        }
    }

    #[async_trait]
    impl ContainerEngine for FakeEngine {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn version(&self) -> Option<String> {
            Some("9.9".to_string())
        }
        async fn ping(&self) -> Result<(), KubeletError> {
            Ok(())
        }
        async fn pod_create(
            &self,
            name: &str,
            labels: &BTreeMap<String, String>,
            _ports: &[PortMappingSpec],
        ) -> Result<String, KubeletError> {
            let id = self.id("pod");
            self.pods.lock().unwrap().push(PodSummary {
                id: id.clone(),
                name: name.to_string(),
                labels: labels.clone(),
                running: false,
                created: Some(1),
            });
            Ok(id)
        }
        async fn pod_start(&self, id: &str) -> Result<(), KubeletError> {
            for pod in self.pods.lock().unwrap().iter_mut() {
                if pod.id == id {
                    pod.running = true;
                }
            }
            Ok(())
        }
        async fn pod_stop(&self, id: &str, _timeout_secs: i64) -> Result<(), KubeletError> {
            for pod in self.pods.lock().unwrap().iter_mut() {
                if pod.id == id {
                    pod.running = false;
                }
            }
            Ok(())
        }
        async fn pod_remove(&self, id: &str) -> Result<(), KubeletError> {
            self.pods.lock().unwrap().retain(|p| p.id != id);
            self.containers.lock().unwrap().retain(|c| c.pod_id != id);
            Ok(())
        }
        async fn pod_list(
            &self,
            filters: &[(&str, &str)],
        ) -> Result<Vec<PodSummary>, KubeletError> {
            Ok(self
                .pods
                .lock()
                .unwrap()
                .iter()
                .filter(|p| {
                    filters
                        .iter()
                        .all(|(k, v)| p.labels.get(*k).map(String::as_str) == Some(*v))
                })
                .cloned()
                .collect())
        }
        async fn pod_ip(&self, _id: &str) -> Result<Option<String>, KubeletError> {
            Ok(Some("10.88.0.7".to_string()))
        }
        async fn container_create(&self, spec: &ContainerSpec) -> Result<String, KubeletError> {
            let id = self.id("c");
            self.containers.lock().unwrap().push(ContainerSummary {
                id: id.clone(),
                name: spec.name.clone(),
                pod_id: spec.pod.clone().unwrap_or_default(),
                image: spec.image.clone(),
                image_id: "sha256:img".to_string(),
                labels: spec.labels.clone(),
                state: ContainerState::Idle("created".to_string()),
                created: Some(2),
            });
            Ok(id)
        }
        async fn container_start(&self, id: &str) -> Result<(), KubeletError> {
            for c in self.containers.lock().unwrap().iter_mut() {
                if c.id == id {
                    c.state = ContainerState::Running {
                        started_at: Some(3),
                    };
                }
            }
            Ok(())
        }
        async fn container_stop(&self, id: &str, timeout_secs: i64) -> Result<(), KubeletError> {
            self.stops
                .lock()
                .unwrap()
                .push((id.to_string(), timeout_secs));
            for c in self.containers.lock().unwrap().iter_mut() {
                if c.id == id {
                    c.state = ContainerState::Exited {
                        exit_code: 143,
                        started_at: Some(3),
                        finished_at: Some(4),
                    };
                }
            }
            Ok(())
        }
        async fn container_remove(&self, id: &str) -> Result<(), KubeletError> {
            self.containers.lock().unwrap().retain(|c| c.id != id);
            Ok(())
        }
        async fn container_list(
            &self,
            filters: &[(&str, &str)],
            pod: Option<&str>,
        ) -> Result<Vec<ContainerSummary>, KubeletError> {
            Ok(self
                .containers
                .lock()
                .unwrap()
                .iter()
                .filter(|c| pod.is_none_or(|p| c.pod_id == p))
                .filter(|c| {
                    filters
                        .iter()
                        .all(|(k, v)| c.labels.get(*k).map(String::as_str) == Some(*v))
                })
                .cloned()
                .collect())
        }
        async fn container_inspect(&self, id: &str) -> Result<ContainerSummary, KubeletError> {
            self.containers
                .lock()
                .unwrap()
                .iter()
                .find(|c| c.id == id)
                .cloned()
                .ok_or_else(|| KubeletError::ContainerOperationFailed {
                    container: id.to_string(),
                    reason: "missing".to_string(),
                })
        }
        async fn image_id(&self, image: &str) -> Result<Option<String>, KubeletError> {
            Ok(self
                .images
                .lock()
                .unwrap()
                .contains(&image.to_string())
                .then(|| "sha256:img".to_string()))
        }
        async fn image_pull(&self, image: &str) -> Result<String, KubeletError> {
            self.images.lock().unwrap().push(image.to_string());
            Ok("sha256:img".to_string())
        }
        async fn logs(&self, id: &str, options: &LogOptions) -> Result<String, KubeletError> {
            Ok(format!(
                "logs {id} {:?} {}",
                options.tail_lines, options.timestamps
            ))
        }
        async fn exec(&self, id: &str, command: &[String]) -> Result<ExecResult, KubeletError> {
            Ok(ExecResult {
                exit_code: 0,
                stdout: format!("{id} {}", command.join(" ")),
                stderr: String::new(),
            })
        }
    }

    #[tokio::test]
    async fn adapter_speaks_cri_over_the_engine() {
        let engine = Arc::new(FakeEngine::default());
        let adapter = EngineRuntimeAdapter::new(engine.clone());
        assert_eq!(adapter.provider_name(), "fake");
        assert_eq!(adapter.runtime_version(), "9.9");

        let sandbox = sandbox_config();
        let sandbox_id = adapter.run_pod_sandbox(&sandbox).await.unwrap();
        assert_eq!(sandbox_id, "pod1");
        let listed = adapter.list_pod_sandbox(None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].state, cri::PodSandboxState::SandboxReady as i32);
        assert_eq!(listed[0].metadata.as_ref().unwrap().name, "hello");
        let status = adapter.pod_sandbox_status(&sandbox_id).await.unwrap();
        assert_eq!(status.network.unwrap().ip, "10.88.0.7");

        let image = cri::ImageSpec {
            image: "localhost/diorama-hello:latest".to_string(),
            ..cri::ImageSpec::default()
        };
        assert!(adapter.image_status(&image).await.unwrap().is_none());
        adapter.pull_image(&image, None).await.unwrap();
        assert_eq!(
            adapter.image_status(&image).await.unwrap().unwrap().id,
            "sha256:img"
        );

        let id = adapter
            .create_container(&sandbox_id, &container_config(0), &sandbox)
            .await
            .unwrap();
        let created = adapter.container_status(&id).await.unwrap();
        assert_eq!(created.state, cri::ContainerState::ContainerCreated as i32);
        adapter.start_container(&id).await.unwrap();
        let filter = cri::ContainerFilter {
            pod_sandbox_id: sandbox_id.clone(),
            ..cri::ContainerFilter::default()
        };
        let containers = adapter.list_containers(Some(&filter)).await.unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(
            containers[0].state,
            cri::ContainerState::ContainerRunning as i32
        );
        assert_eq!(containers[0].metadata.as_ref().unwrap().name, "hello");
        assert_eq!(
            adapter
                .exec_sync(&id, &["true".to_string()], 5)
                .await
                .unwrap()
                .stdout,
            "c2 true"
        );
        assert_eq!(
            adapter
                .container_logs(&id, &LogOptions::default())
                .await
                .unwrap(),
            "logs c2 None false"
        );

        adapter.stop_container(&id, 7).await.unwrap();
        assert_eq!(*engine.stops.lock().unwrap(), vec![(id.clone(), 7)]);
        let stopped = adapter.container_status(&id).await.unwrap();
        assert_eq!(stopped.state, cri::ContainerState::ContainerExited as i32);
        assert_eq!(stopped.exit_code, 143);
        adapter.remove_container(&id).await.unwrap();
        adapter.stop_pod_sandbox(&sandbox_id).await.unwrap();
        assert_eq!(
            adapter.list_pod_sandbox(None).await.unwrap()[0].state,
            cri::PodSandboxState::SandboxNotready as i32
        );
        adapter.remove_pod_sandbox(&sandbox_id).await.unwrap();
        assert!(adapter.list_pod_sandbox(None).await.unwrap().is_empty());
    }
}
