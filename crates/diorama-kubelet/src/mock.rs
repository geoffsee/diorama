//! In-memory CRI runtime for tests and fixtures.
//!
//! Sandboxes and containers live in a map and move through the CRI states on
//! the kubelet's calls. Nothing executes; `exec_sync` answers from scripted
//! responses and probe results, and logs come from scripted text.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;

use crate::error::KubeletError;
use crate::workload::{
    ExecResult, LABEL_CONTAINER_NAME, LABEL_POD_UID, LogOptions, RuntimeProvider, cri,
    nanos_from_secs,
};

#[derive(Debug, Clone)]
struct SandboxRecord {
    config: cri::PodSandboxConfig,
    state: cri::PodSandboxState,
    created_at: i64,
}

#[derive(Debug, Clone)]
struct ContainerRecord {
    sandbox_id: String,
    config: cri::ContainerConfig,
    state: cri::ContainerState,
    created_at: i64,
    started_at: i64,
    finished_at: i64,
    exit_code: i32,
}

#[derive(Debug, Default)]
struct MockState {
    sandboxes: BTreeMap<String, SandboxRecord>,
    containers: BTreeMap<String, ContainerRecord>,
    logs: BTreeMap<String, String>,
    exec_responses: BTreeMap<String, ExecResult>,
    probe_results: BTreeMap<String, bool>,
    stop_calls: Vec<(String, i64)>,
    exec_calls: Vec<(String, Vec<String>)>,
}

/// Simulated runtime provider implementing the CRI subset in memory.
#[derive(Debug)]
pub struct MockRuntimeProvider {
    name: String,
    is_external: bool,
    next_id: AtomicUsize,
    state: Mutex<MockState>,
}

impl MockRuntimeProvider {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            is_external: false,
            next_id: AtomicUsize::new(1),
            state: Mutex::new(MockState::default()),
        }
    }

    #[must_use]
    pub fn new_external(name: impl Into<String>) -> Self {
        let mut provider = Self::new(name);
        provider.is_external = true;
        provider
    }

    pub fn set_external(&mut self, external: bool) {
        self.is_external = external;
    }

    /// Scripts the log text for a container, keyed by `name` or `"<pod uid>:<name>"`.
    pub fn set_container_logs(&self, key: impl Into<String>, logs: impl Into<String>) {
        self.lock().logs.insert(key.into(), logs.into());
    }

    /// Scripts an exec result, keyed by `"<container>:<cmd>"`, `"<cmd>"` or the program name.
    pub fn set_exec_response(&self, key: impl Into<String>, response: ExecResult) {
        self.lock().exec_responses.insert(key.into(), response);
    }

    pub fn set_probe_result(&self, key: impl Into<String>, success: bool) {
        self.lock().probe_results.insert(key.into(), success);
    }

    /// Whether a ready sandbox exists for the pod uid.
    pub fn is_pod_active(&self, pod_uid: &str) -> bool {
        self.lock().sandboxes.values().any(|s| {
            s.state == cri::PodSandboxState::SandboxReady
                && s.config.labels.get(LABEL_POD_UID).map(String::as_str) == Some(pod_uid)
        })
    }

    /// Simulates the latest attempt of a container exiting with `exit_code`.
    pub fn set_container_exit(&self, pod_uid: &str, container_name: &str, exit_code: i32) {
        let now = now_nanos();
        let mut state = self.lock();
        let sandbox_ids: Vec<String> = state
            .sandboxes
            .iter()
            .filter(|(_, s)| {
                s.config.labels.get(LABEL_POD_UID).map(String::as_str) == Some(pod_uid)
            })
            .map(|(id, _)| id.clone())
            .collect();
        let latest = state
            .containers
            .iter()
            .filter(|(_, c)| {
                sandbox_ids.contains(&c.sandbox_id)
                    && c.config.metadata.as_ref().map(|m| m.name.as_str()) == Some(container_name)
            })
            .max_by_key(|(_, c)| c.config.metadata.as_ref().map_or(0, |m| m.attempt))
            .map(|(id, _)| id.clone());
        if let Some(record) = latest.and_then(|id| state.containers.get_mut(&id)) {
            record.state = cri::ContainerState::ContainerExited;
            record.exit_code = exit_code;
            record.finished_at = now;
        }
    }

    /// Ids of the containers created for a pod uid, in creation order.
    pub fn container_ids(&self, pod_uid: &str) -> Vec<String> {
        let state = self.lock();
        let sandbox_ids: Vec<String> = state
            .sandboxes
            .iter()
            .filter(|(_, s)| {
                s.config.labels.get(LABEL_POD_UID).map(String::as_str) == Some(pod_uid)
            })
            .map(|(id, _)| id.clone())
            .collect();
        state
            .containers
            .iter()
            .filter(|(_, c)| sandbox_ids.contains(&c.sandbox_id))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// `(container id, timeout)` of every `stop_container` call so far.
    pub fn stop_calls(&self) -> Vec<(String, i64)> {
        self.lock().stop_calls.clone()
    }

    /// `(container id, cmd)` of every `exec_sync` call so far.
    pub fn exec_calls(&self) -> Vec<(String, Vec<String>)> {
        self.lock().exec_calls.clone()
    }

    /// Number of sandboxes still known for a pod uid, in any state.
    pub fn sandbox_count(&self, pod_uid: &str) -> usize {
        self.lock()
            .sandboxes
            .values()
            .filter(|s| s.config.labels.get(LABEL_POD_UID).map(String::as_str) == Some(pod_uid))
            .count()
    }

    /// Pod sandbox configs created for a pod uid.
    pub fn sandbox_configs(&self, pod_uid: &str) -> Vec<cri::PodSandboxConfig> {
        self.lock()
            .sandboxes
            .values()
            .filter(|s| s.config.labels.get(LABEL_POD_UID).map(String::as_str) == Some(pod_uid))
            .map(|s| s.config.clone())
            .collect()
    }

    /// Container configs created for a pod uid.
    pub fn container_configs(&self, pod_uid: &str) -> Vec<cri::ContainerConfig> {
        let state = self.lock();
        let sandbox_ids: Vec<String> = state
            .sandboxes
            .iter()
            .filter(|(_, s)| {
                s.config.labels.get(LABEL_POD_UID).map(String::as_str) == Some(pod_uid)
            })
            .map(|(id, _)| id.clone())
            .collect();
        state
            .containers
            .values()
            .filter(|c| sandbox_ids.contains(&c.sandbox_id))
            .map(|c| c.config.clone())
            .collect()
    }

    fn lock(&self) -> MutexGuard<'_, MockState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn next(&self, kind: &str) -> String {
        format!(
            "{}-{kind}-{}",
            self.name,
            self.next_id.fetch_add(1, Ordering::SeqCst)
        )
    }

    fn missing(id: &str) -> KubeletError {
        KubeletError::ContainerOperationFailed {
            container: id.to_string(),
            reason: "unknown id".to_string(),
        }
    }
}

fn now_nanos() -> i64 {
    nanos_from_secs(diorama_apiserver::time::now_unix())
}

fn to_container(id: &str, record: &ContainerRecord) -> cri::Container {
    cri::Container {
        id: id.to_string(),
        pod_sandbox_id: record.sandbox_id.clone(),
        metadata: record.config.metadata.clone(),
        image: record.config.image.clone(),
        image_ref: record
            .config
            .image
            .as_ref()
            .map(|i| format!("sha256:mock-{}", i.image))
            .unwrap_or_default(),
        state: record.state as i32,
        created_at: record.created_at,
        labels: record.config.labels.clone(),
        annotations: record.config.annotations.clone(),
        image_id: String::new(),
    }
}

fn matches_labels(labels: &BTreeMap<String, String>, selector: &BTreeMap<String, String>) -> bool {
    selector.iter().all(|(k, v)| labels.get(k) == Some(v))
}

fn resolve_exec_cat(record: &ContainerRecord, target_path: &str) -> Option<ExecResult> {
    let mount = record
        .config
        .mounts
        .iter()
        .filter(|m| {
            target_path == m.container_path
                || target_path.starts_with(&format!("{}/", m.container_path.trim_end_matches('/')))
        })
        .max_by_key(|m| m.container_path.len())?;

    let rel = target_path
        .strip_prefix(mount.container_path.trim_end_matches('/'))
        .unwrap_or("")
        .trim_start_matches('/');
    let host_file = if rel.is_empty() {
        std::path::PathBuf::from(&mount.host_path)
    } else {
        std::path::Path::new(&mount.host_path).join(rel)
    };
    match std::fs::read_to_string(&host_file) {
        Ok(content) => Some(ExecResult {
            exit_code: 0,
            stdout: content,
            stderr: String::new(),
        }),
        Err(err) => Some(ExecResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: format!("{target_path}: {err}\n"),
        }),
    }
}

#[async_trait]
impl RuntimeProvider for MockRuntimeProvider {
    fn provider_name(&self) -> &str {
        &self.name
    }

    fn is_external(&self) -> bool {
        self.is_external
    }

    async fn run_pod_sandbox(
        &self,
        config: &cri::PodSandboxConfig,
    ) -> Result<String, KubeletError> {
        let id = self.next("sb");
        self.lock().sandboxes.insert(
            id.clone(),
            SandboxRecord {
                config: config.clone(),
                state: cri::PodSandboxState::SandboxReady,
                created_at: now_nanos(),
            },
        );
        Ok(id)
    }

    async fn stop_pod_sandbox(&self, pod_sandbox_id: &str) -> Result<(), KubeletError> {
        let now = now_nanos();
        let mut state = self.lock();
        let sandbox = state
            .sandboxes
            .get_mut(pod_sandbox_id)
            .ok_or_else(|| Self::missing(pod_sandbox_id))?;
        sandbox.state = cri::PodSandboxState::SandboxNotready;
        for container in state.containers.values_mut() {
            if container.sandbox_id == pod_sandbox_id
                && container.state == cri::ContainerState::ContainerRunning
            {
                container.state = cri::ContainerState::ContainerExited;
                container.finished_at = now;
                container.exit_code = 137;
            }
        }
        Ok(())
    }

    async fn remove_pod_sandbox(&self, pod_sandbox_id: &str) -> Result<(), KubeletError> {
        let mut state = self.lock();
        state
            .containers
            .retain(|_, c| c.sandbox_id != pod_sandbox_id);
        state.sandboxes.remove(pod_sandbox_id);
        Ok(())
    }

    async fn list_pod_sandbox(
        &self,
        filter: Option<&cri::PodSandboxFilter>,
    ) -> Result<Vec<cri::PodSandbox>, KubeletError> {
        Ok(self
            .lock()
            .sandboxes
            .iter()
            .filter(|(id, s)| {
                filter.is_none_or(|f| {
                    (f.id.is_empty() || f.id == **id)
                        && f.state.as_ref().is_none_or(|st| st.state == s.state as i32)
                        && matches_labels(&s.config.labels, &f.label_selector)
                })
            })
            .map(|(id, s)| cri::PodSandbox {
                id: id.clone(),
                metadata: s.config.metadata.clone(),
                state: s.state as i32,
                created_at: s.created_at,
                labels: s.config.labels.clone(),
                annotations: s.config.annotations.clone(),
                runtime_handler: String::new(),
            })
            .collect())
    }

    async fn pod_sandbox_status(
        &self,
        pod_sandbox_id: &str,
    ) -> Result<cri::PodSandboxStatus, KubeletError> {
        let state = self.lock();
        let sandbox = state
            .sandboxes
            .get(pod_sandbox_id)
            .ok_or_else(|| Self::missing(pod_sandbox_id))?;
        Ok(cri::PodSandboxStatus {
            id: pod_sandbox_id.to_string(),
            metadata: sandbox.config.metadata.clone(),
            state: sandbox.state as i32,
            created_at: sandbox.created_at,
            network: None,
            linux: None,
            labels: sandbox.config.labels.clone(),
            annotations: sandbox.config.annotations.clone(),
            runtime_handler: String::new(),
        })
    }

    async fn create_container(
        &self,
        pod_sandbox_id: &str,
        config: &cri::ContainerConfig,
        _sandbox_config: &cri::PodSandboxConfig,
    ) -> Result<String, KubeletError> {
        let id = self.next("c");
        let mut state = self.lock();
        if !state.sandboxes.contains_key(pod_sandbox_id) {
            return Err(Self::missing(pod_sandbox_id));
        }
        state.containers.insert(
            id.clone(),
            ContainerRecord {
                sandbox_id: pod_sandbox_id.to_string(),
                config: config.clone(),
                state: cri::ContainerState::ContainerCreated,
                created_at: now_nanos(),
                started_at: 0,
                finished_at: 0,
                exit_code: 0,
            },
        );
        Ok(id)
    }

    async fn start_container(&self, container_id: &str) -> Result<(), KubeletError> {
        let mut state = self.lock();
        let container = state
            .containers
            .get_mut(container_id)
            .ok_or_else(|| Self::missing(container_id))?;
        container.state = cri::ContainerState::ContainerRunning;
        container.started_at = now_nanos();
        Ok(())
    }

    async fn stop_container(
        &self,
        container_id: &str,
        timeout_secs: i64,
    ) -> Result<(), KubeletError> {
        let mut state = self.lock();
        state
            .stop_calls
            .push((container_id.to_string(), timeout_secs));
        let container = state
            .containers
            .get_mut(container_id)
            .ok_or_else(|| Self::missing(container_id))?;
        if container.state == cri::ContainerState::ContainerRunning {
            container.state = cri::ContainerState::ContainerExited;
            container.finished_at = now_nanos();
            container.exit_code = 0;
        }
        Ok(())
    }

    async fn remove_container(&self, container_id: &str) -> Result<(), KubeletError> {
        self.lock().containers.remove(container_id);
        Ok(())
    }

    async fn list_containers(
        &self,
        filter: Option<&cri::ContainerFilter>,
    ) -> Result<Vec<cri::Container>, KubeletError> {
        Ok(self
            .lock()
            .containers
            .iter()
            .filter(|(id, c)| {
                filter.is_none_or(|f| {
                    (f.id.is_empty() || f.id == **id)
                        && (f.pod_sandbox_id.is_empty() || f.pod_sandbox_id == c.sandbox_id)
                        && f.state.as_ref().is_none_or(|st| st.state == c.state as i32)
                        && matches_labels(&c.config.labels, &f.label_selector)
                })
            })
            .map(|(id, c)| to_container(id, c))
            .collect())
    }

    async fn container_status(
        &self,
        container_id: &str,
    ) -> Result<cri::ContainerStatus, KubeletError> {
        let state = self.lock();
        let record = state
            .containers
            .get(container_id)
            .ok_or_else(|| Self::missing(container_id))?;
        let listed = to_container(container_id, record);
        Ok(cri::ContainerStatus {
            id: container_id.to_string(),
            metadata: record.config.metadata.clone(),
            state: record.state as i32,
            created_at: record.created_at,
            started_at: record.started_at,
            finished_at: record.finished_at,
            exit_code: record.exit_code,
            image: record.config.image.clone(),
            image_ref: listed.image_ref,
            reason: String::new(),
            message: String::new(),
            labels: record.config.labels.clone(),
            annotations: record.config.annotations.clone(),
            mounts: record.config.mounts.clone(),
            log_path: record.config.log_path.clone(),
            resources: record.config.linux.as_ref().and_then(|l| {
                l.resources.as_ref().map(|res| cri::ContainerResources {
                    linux: Some(res.clone()),
                    windows: None,
                })
            }),
            image_id: String::new(),
            user: None,
            stop_signal: 0,
        })
    }

    async fn exec_sync(
        &self,
        container_id: &str,
        cmd: &[String],
        _timeout_secs: i64,
    ) -> Result<ExecResult, KubeletError> {
        let mut state = self.lock();
        state
            .exec_calls
            .push((container_id.to_string(), cmd.to_vec()));
        let container_name = state
            .containers
            .get(container_id)
            .and_then(|c| c.config.metadata.as_ref())
            .map(|m| m.name.clone())
            .unwrap_or_default();
        let cmd_str = cmd.join(" ");
        let key_full = format!("{container_name}:{cmd_str}");
        let key_id_cmd = format!("{container_id}:{cmd_str}");
        if let Some(res) = state
            .exec_responses
            .get(&key_full)
            .or_else(|| state.exec_responses.get(&key_id_cmd))
            .or_else(|| state.exec_responses.get(&cmd_str))
            .or_else(|| cmd.first().and_then(|c| state.exec_responses.get(c)))
        {
            return Ok(res.clone());
        }
        if let Some(&pass) = state
            .probe_results
            .get(&key_full)
            .or_else(|| state.probe_results.get(&key_id_cmd))
            .or_else(|| state.probe_results.get(&cmd_str))
            .or_else(|| state.probe_results.get(&container_name))
            .or_else(|| state.probe_results.get(container_id))
        {
            return Ok(ExecResult {
                exit_code: i32::from(!pass),
                stdout: if pass {
                    "probe succeeded\n"
                } else {
                    "probe failed\n"
                }
                .to_string(),
                stderr: if pass {
                    String::new()
                } else {
                    "failure\n".to_string()
                },
            });
        }
        if (cmd.first().is_some_and(|c| c == "cat" || c == "/bin/cat")) && cmd.len() >= 2 {
            let target_path = &cmd[1];
            if let Some(record) = state.containers.get(container_id)
                && let Some(res) = resolve_exec_cat(record, target_path)
            {
                return Ok(res);
            }
        }
        if cmd.first().is_some_and(|c| c == "echo") {
            return Ok(ExecResult {
                exit_code: 0,
                stdout: format!("{}\n", cmd[1..].join(" ")),
                stderr: String::new(),
            });
        }
        Ok(ExecResult {
            exit_code: 0,
            stdout: format!("executed: {cmd_str}\n"),
            stderr: String::new(),
        })
    }

    async fn container_logs(
        &self,
        container_id: &str,
        options: &LogOptions,
    ) -> Result<String, KubeletError> {
        let state = self.lock();
        let record = state
            .containers
            .get(container_id)
            .ok_or_else(|| Self::missing(container_id))?;
        let name = record
            .config
            .labels
            .get(LABEL_CONTAINER_NAME)
            .cloned()
            .unwrap_or_default();
        let uid = record
            .config
            .labels
            .get(LABEL_POD_UID)
            .cloned()
            .unwrap_or_default();
        let raw = state
            .logs
            .get(&format!("{uid}:{name}"))
            .or_else(|| state.logs.get(&name))
            .cloned()
            .unwrap_or_else(|| format!("container {name} is running in {}\n", record.sandbox_id));
        Ok(match options.tail_lines {
            Some(n) => {
                let lines: Vec<&str> = raw.lines().collect();
                let tailed = lines[lines.len().saturating_sub(n)..].join("\n");
                if raw.ends_with('\n') && !tailed.is_empty() {
                    format!("{tailed}\n")
                } else {
                    tailed
                }
            },
            None => raw,
        })
    }

    async fn image_status(
        &self,
        image: &cri::ImageSpec,
    ) -> Result<Option<cri::Image>, KubeletError> {
        Ok(Some(cri::Image {
            id: format!("sha256:mock-{}", image.image),
            repo_tags: vec![image.image.clone()],
            repo_digests: Vec::new(),
            size: 0,
            uid: None,
            username: String::new(),
            spec: Some(image.clone()),
            pinned: false,
        }))
    }

    async fn pull_image(
        &self,
        image: &cri::ImageSpec,
        _sandbox_config: Option<&cri::PodSandboxConfig>,
    ) -> Result<String, KubeletError> {
        Ok(format!("sha256:mock-{}", image.image))
    }
}
