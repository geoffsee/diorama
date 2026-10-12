//! Podman engine for [`EngineRuntimeAdapter`](crate::engine::EngineRuntimeAdapter).
//!
//! This module knows only the `podman` command line: pods (`pod create/start/
//! stop/rm/ps`), containers (`create/start/stop/rm/ps`), images (`image
//! inspect`, `pull`), `logs` and `exec`, and how to read `--format json`.
//! Every invocation goes through [`PodmanEngine::podman`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use async_trait::async_trait;
use serde::Deserialize;

use crate::engine::{
    ContainerEngine, ContainerSpec, ContainerState, ContainerSummary, PodSummary, PortMappingSpec,
};
use crate::error::KubeletError;
use crate::workload::{ExecResult, LogOptions};

const ENGINE_NAME: &str = "podman";
const SEARCH_LOCATIONS: &[&str] = &[
    "/opt/podman/bin/podman",
    "/opt/homebrew/bin/podman",
    "/usr/local/bin/podman",
    "/usr/bin/podman",
];

/// Drives pods and containers through the `podman` command-line client.
#[derive(Clone, Debug)]
pub struct PodmanEngine {
    binary: PathBuf,
    version: Option<String>,
}

impl PodmanEngine {
    #[must_use]
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            version: None,
        }
    }

    /// Records the client version reported by `podman --version`.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Finds `podman` on `PATH` or in the usual install locations and reads its version.
    #[must_use]
    pub fn detect() -> Option<Self> {
        let from_path = std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("podman"))
                .find(|candidate| candidate.is_file())
        });
        from_path
            .or_else(|| {
                SEARCH_LOCATIONS
                    .iter()
                    .map(PathBuf::from)
                    .find(|candidate| candidate.is_file())
            })
            .map(|binary| {
                let version = std::process::Command::new(&binary)
                    .arg("--version")
                    .output()
                    .ok()
                    .filter(|output| output.status.success())
                    .and_then(|output| parse_version(&String::from_utf8_lossy(&output.stdout)));
                let engine = Self::new(binary);
                match version {
                    Some(version) => engine.with_version(version),
                    None => engine,
                }
            })
    }

    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    fn unavailable(&self, e: &std::io::Error, what: &str) -> KubeletError {
        KubeletError::RuntimeUnavailable {
            endpoint: self.binary.display().to_string(),
            reason: format!("failed to execute podman {what}: {e}"),
        }
    }

    fn command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.binary);
        cmd.kill_on_drop(true);
        cmd
    }

    /// Runs one podman command and returns its output. Spawn failures mean the
    /// engine is unavailable; nonzero exits carry stderr.
    async fn podman(
        &self,
        args: &[String],
        context: &str,
    ) -> Result<std::process::Output, KubeletError> {
        let verb = args.first().map_or("", String::as_str);
        let output = self
            .command()
            .args(args)
            .output()
            .await
            .map_err(|e| self.unavailable(&e, verb))?;
        if !output.status.success() {
            return Err(KubeletError::ContainerOperationFailed {
                container: context.to_string(),
                reason: format!(
                    "podman {} exited with {}: {}",
                    args.iter()
                        .take(2)
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(" "),
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        Ok(output)
    }

    async fn podman_stdout(&self, args: &[String], context: &str) -> Result<String, KubeletError> {
        let output = self.podman(args, context).await?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    async fn ps(
        &self,
        label_filters: &[(&str, &str)],
        pod: Option<&str>,
        id: Option<&str>,
    ) -> Result<Vec<ContainerSummary>, KubeletError> {
        let mut args = vec!["ps".to_string(), "--all".to_string()];
        for (key, value) in label_filters {
            args.push("--filter".to_string());
            args.push(format!("label={key}={value}"));
        }
        if let Some(pod) = pod {
            args.push("--filter".to_string());
            args.push(format!("pod={pod}"));
        }
        if let Some(id) = id {
            args.push("--filter".to_string());
            args.push(format!("id={id}"));
        }
        args.push("--format".to_string());
        args.push("json".to_string());
        let stdout = self.podman_stdout(&args, "ps").await?;
        Ok(parse_ps_output(&stdout)?
            .into_iter()
            .filter(|entry| !entry.is_infra)
            .map(PsEntry::into_summary)
            .collect())
    }
}

fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
}

#[async_trait]
impl ContainerEngine for PodmanEngine {
    fn name(&self) -> &str {
        ENGINE_NAME
    }

    fn version(&self) -> Option<String> {
        self.version.clone()
    }

    async fn ping(&self) -> Result<(), KubeletError> {
        self.podman(
            &strings(&["version", "--format", "{{.Client.Version}}"]),
            "version",
        )
        .await
        .map(drop)
        .map_err(|e| KubeletError::RuntimeUnavailable {
            endpoint: self.binary.display().to_string(),
            reason: e.to_string(),
        })
    }

    async fn pod_create(
        &self,
        name: &str,
        labels: &BTreeMap<String, String>,
        ports: &[PortMappingSpec],
    ) -> Result<String, KubeletError> {
        let args = pod_create_arguments(name, labels, ports);
        self.podman_stdout(&args, name).await
    }

    async fn pod_start(&self, id: &str) -> Result<(), KubeletError> {
        self.podman(&strings(&["pod", "start", id]), id)
            .await
            .map(drop)
    }

    async fn pod_stop(&self, id: &str, timeout_secs: i64) -> Result<(), KubeletError> {
        let timeout = timeout_secs.max(0).to_string();
        self.podman(&strings(&["pod", "stop", "--time", &timeout, id]), id)
            .await
            .map(drop)
    }

    async fn pod_remove(&self, id: &str) -> Result<(), KubeletError> {
        self.podman(&strings(&["pod", "rm", "--force", id]), id)
            .await
            .map(drop)
    }

    async fn pod_list(
        &self,
        label_filters: &[(&str, &str)],
    ) -> Result<Vec<PodSummary>, KubeletError> {
        let mut args = strings(&["pod", "ps"]);
        for (key, value) in label_filters {
            args.push("--filter".to_string());
            args.push(format!("label={key}={value}"));
        }
        args.push("--format".to_string());
        args.push("json".to_string());
        let stdout = self.podman_stdout(&args, "pod ps").await?;
        Ok(parse_pod_ps_output(&stdout)?
            .into_iter()
            .map(PodPsEntry::into_summary)
            .collect())
    }

    /// The infra container holds the pod's network namespace, so its address is the pod IP.
    async fn pod_ip(&self, id: &str) -> Result<Option<String>, KubeletError> {
        let infra = self
            .podman_stdout(
                &strings(&["pod", "inspect", "--format", "{{.InfraContainerID}}", id]),
                id,
            )
            .await?;
        if infra.is_empty() {
            return Ok(None);
        }
        let addresses = self
            .podman_stdout(
                &strings(&[
                    "inspect",
                    "--format",
                    "{{.NetworkSettings.IPAddress}} {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                    &infra,
                ]),
                id,
            )
            .await?;
        Ok(addresses
            .split_whitespace()
            .find(|ip| !ip.is_empty())
            .map(str::to_owned))
    }

    async fn container_create(&self, spec: &ContainerSpec) -> Result<String, KubeletError> {
        let args = create_arguments(spec)?;
        self.podman_stdout(&args, &spec.name).await
    }

    async fn container_start(&self, id: &str) -> Result<(), KubeletError> {
        self.podman(&strings(&["start", id]), id).await.map(drop)
    }

    async fn container_stop(&self, id: &str, timeout_secs: i64) -> Result<(), KubeletError> {
        let timeout = timeout_secs.max(0).to_string();
        self.podman(&strings(&["stop", "--time", &timeout, id]), id)
            .await
            .map(drop)
    }

    async fn container_remove(&self, id: &str) -> Result<(), KubeletError> {
        self.podman(&strings(&["rm", "--force", id]), id)
            .await
            .map(drop)
    }

    async fn container_list(
        &self,
        label_filters: &[(&str, &str)],
        pod: Option<&str>,
    ) -> Result<Vec<ContainerSummary>, KubeletError> {
        self.ps(label_filters, pod, None).await
    }

    async fn container_inspect(&self, id: &str) -> Result<ContainerSummary, KubeletError> {
        self.ps(&[], None, Some(id))
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| KubeletError::ContainerOperationFailed {
                container: id.to_string(),
                reason: "container not found".to_string(),
            })
    }

    async fn image_id(&self, image: &str) -> Result<Option<String>, KubeletError> {
        let output = self
            .command()
            .args(["image", "inspect", "--format", "{{.Id}}", image])
            .output()
            .await
            .map_err(|e| self.unavailable(&e, "image inspect"))?;
        if !output.status.success() {
            return Ok(None);
        }
        let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok((!id.is_empty()).then(|| prefix_sha(&id)))
    }

    async fn image_pull(&self, image: &str) -> Result<String, KubeletError> {
        let stdout = self
            .podman_stdout(&strings(&["pull", "--quiet", image]), image)
            .await?;
        Ok(prefix_sha(stdout.lines().last().unwrap_or("").trim()))
    }

    /// `podman logs` replays the container's log in time order but writes each
    /// entry to its original stream. Both streams are joined onto one pipe so the
    /// order survives, as it does in a CRI log file.
    async fn logs(&self, id: &str, options: &LogOptions) -> Result<String, KubeletError> {
        let args = log_arguments(id, options);
        let (reader, writer) = std::io::pipe().map_err(|e| self.unavailable(&e, "logs"))?;
        let stderr_writer = writer
            .try_clone()
            .map_err(|e| self.unavailable(&e, "logs"))?;
        let mut child = self
            .command()
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(stderr_writer))
            .spawn()
            .map_err(|e| self.unavailable(&e, "logs"))?;
        let collect = tokio::task::spawn_blocking(move || {
            let mut reader = reader;
            let mut buffer = Vec::new();
            std::io::Read::read_to_end(&mut reader, &mut buffer).map(|_| buffer)
        });
        let status = child
            .wait()
            .await
            .map_err(|e| self.unavailable(&e, "logs"))?;
        let output = collect
            .await
            .map_err(|e| KubeletError::ContainerOperationFailed {
                container: id.to_string(),
                reason: format!("log reader task failed: {e}"),
            })?
            .map_err(|e| self.unavailable(&e, "logs"))?;
        let text = String::from_utf8_lossy(&output).into_owned();
        if !status.success() {
            return Err(KubeletError::ContainerOperationFailed {
                container: id.to_string(),
                reason: format!("podman logs exited with {status}: {}", text.trim()),
            });
        }
        Ok(text)
    }

    async fn exec(&self, id: &str, command: &[String]) -> Result<ExecResult, KubeletError> {
        let mut args = strings(&["exec", id]);
        args.extend(command.iter().cloned());
        let output = self
            .command()
            .args(&args)
            .output()
            .await
            .map_err(|e| self.unavailable(&e, "exec"))?;
        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn prefix_sha(id: &str) -> String {
    if id.is_empty() || id.contains(':') {
        id.to_string()
    } else {
        format!("sha256:{id}")
    }
}

/// Builds the `podman pod create` argument vector.
pub fn pod_create_arguments(
    name: &str,
    labels: &BTreeMap<String, String>,
    ports: &[PortMappingSpec],
) -> Vec<String> {
    let mut args = strings(&["pod", "create", "--name", name]);
    for port in ports {
        args.push("-p".to_string());
        args.push(port.to_argument());
    }
    for (key, value) in labels {
        args.push("--label".to_string());
        args.push(format!("{key}={value}"));
    }
    args
}

/// Builds the `podman create` argument vector for one container spec.
///
/// The kubelet has already pulled the image, so the engine never pulls here.
pub fn create_arguments(spec: &ContainerSpec) -> Result<Vec<String>, KubeletError> {
    let mut args = strings(&["create", "--name", &spec.name, "--pull", "never"]);
    if let Some(pod) = &spec.pod {
        args.push("--pod".to_string());
        args.push(pod.clone());
    }
    for (key, value) in &spec.labels {
        args.push("--label".to_string());
        args.push(format!("{key}={value}"));
    }
    for (key, value) in &spec.env {
        args.push("--env".to_string());
        args.push(format!("{key}={value}"));
    }
    if let Some(dir) = &spec.working_dir {
        args.push("--workdir".to_string());
        args.push(dir.clone());
    }
    if let Some(entrypoint) = &spec.entrypoint {
        args.push("--entrypoint".to_string());
        args.push(serde_json::to_string(entrypoint)?);
    }
    for mount in &spec.mounts {
        args.push("-v".to_string());
        let ro = if mount.readonly { ":ro" } else { "" };
        args.push(format!("{}:{}{ro}", mount.host_path, mount.container_path));
    }
    if let Some(res) = &spec.resources {
        if let Some(shares) = res.cpu_shares {
            args.push("--cpu-shares".to_string());
            args.push(shares.to_string());
        }
        if let Some(quota) = res.cpu_quota {
            args.push("--cpu-quota".to_string());
            args.push(quota.to_string());
        }
        if let Some(period) = res.cpu_period {
            args.push("--cpu-period".to_string());
            args.push(period.to_string());
        }
        if let Some(cpus) = &res.cpuset_cpus {
            args.push("--cpuset-cpus".to_string());
            args.push(cpus.clone());
        }
        if let Some(mem) = res.memory_limit_in_bytes {
            args.push("--memory".to_string());
            args.push(mem.to_string());
        }
    }
    args.push(spec.image.clone());
    args.extend(spec.args.iter().cloned());
    Ok(args)
}

/// Builds the `podman logs` argument vector.
pub fn log_arguments(id: &str, options: &LogOptions) -> Vec<String> {
    let mut args = vec!["logs".to_string()];
    if options.follow {
        args.push("--follow".to_string());
    }
    if let Some(tail) = options.tail_lines {
        args.push("--tail".to_string());
        args.push(tail.to_string());
    }
    if options.timestamps {
        args.push("--timestamps".to_string());
    }
    if let Some(since) = options.since_seconds {
        args.push("--since".to_string());
        args.push(format!("{since}s"));
    }
    args.push(id.to_string());
    args
}

fn deserialize_null_as_empty_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<BTreeMap<String, String>>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// One row of `podman ps --format json`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct PsEntry {
    pub id: String,
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub pod: String,
    /// Podman copies pod labels onto the infra container; it is not a workload container.
    #[serde(default, rename = "IsInfra")]
    pub is_infra: bool,
    #[serde(default)]
    pub image: String,
    #[serde(default, rename = "ImageID")]
    pub image_id: String,
    #[serde(default, deserialize_with = "deserialize_null_as_empty_map")]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub exit_code: i32,
    #[serde(default)]
    pub started_at: i64,
    #[serde(default)]
    pub exited_at: i64,
    #[serde(default)]
    pub created: i64,
}

impl PsEntry {
    fn into_summary(self) -> ContainerSummary {
        // Podman prints Go's zero time (negative) for timestamps it has not set.
        let started_at = u64::try_from(self.started_at).ok();
        let state = match self.state.as_str() {
            "running" => ContainerState::Running { started_at },
            "exited" | "stopped" => ContainerState::Exited {
                exit_code: self.exit_code,
                started_at,
                finished_at: u64::try_from(self.exited_at).ok(),
            },
            other => ContainerState::Idle(if other.is_empty() {
                "unknown".to_string()
            } else {
                other.to_string()
            }),
        };
        ContainerSummary {
            id: self.id,
            name: self.names.into_iter().next().unwrap_or_default(),
            pod_id: self.pod,
            image: self.image,
            image_id: prefix_sha(&self.image_id),
            labels: self.labels,
            state,
            created: u64::try_from(self.created).ok().filter(|c| *c > 0),
        }
    }
}

/// One row of `podman pod ps --format json`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct PodPsEntry {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, deserialize_with = "deserialize_null_as_empty_map")]
    pub labels: BTreeMap<String, String>,
}

impl PodPsEntry {
    fn into_summary(self) -> PodSummary {
        PodSummary {
            id: self.id,
            name: self.name,
            labels: self.labels,
            // A pod is up while its infra container runs; `Degraded` means some
            // workload containers exited but the sandbox is still there.
            running: matches!(self.status.as_str(), "Running" | "Degraded"),
            created: None,
        }
    }
}

/// Parses `podman ps --format json`; an empty list prints `[]` or nothing.
pub fn parse_ps_output(stdout: &str) -> Result<Vec<PsEntry>, KubeletError> {
    parse_json_list(stdout, "ps")
}

/// Parses `podman pod ps --format json`.
pub fn parse_pod_ps_output(stdout: &str) -> Result<Vec<PodPsEntry>, KubeletError> {
    parse_json_list(stdout, "pod ps")
}

fn parse_json_list<T: serde::de::DeserializeOwned>(
    stdout: &str,
    what: &str,
) -> Result<Vec<T>, KubeletError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed).map_err(|e| KubeletError::ContainerOperationFailed {
        container: what.to_string(),
        reason: format!("podman {what} output is not JSON: {e}"),
    })
}

/// Extracts `6.0.2` from `podman version 6.0.2`.
fn parse_version(stdout: &str) -> Option<String> {
    stdout
        .split_whitespace()
        .last()
        .filter(|v| v.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{MountSpec, ResourceSpec};

    #[test]
    fn create_arguments_spell_the_podman_command_line() {
        let spec = ContainerSpec {
            name: "k8s_hello_hello_default_u1_0".to_string(),
            image: "localhost/diorama-hello:latest".to_string(),
            pod: Some("pod1".to_string()),
            entrypoint: Some(vec!["/diorama-hello".to_string()]),
            args: vec!["600".to_string()],
            env: vec![("GREETING".to_string(), "hi".to_string())],
            working_dir: Some("/work".to_string()),
            labels: BTreeMap::from([("io.kubernetes.pod.uid".to_string(), "u1".to_string())]),
            ..ContainerSpec::default()
        };
        assert_eq!(
            create_arguments(&spec).unwrap(),
            [
                "create",
                "--name",
                "k8s_hello_hello_default_u1_0",
                "--pull",
                "never",
                "--pod",
                "pod1",
                "--label",
                "io.kubernetes.pod.uid=u1",
                "--env",
                "GREETING=hi",
                "--workdir",
                "/work",
                "--entrypoint",
                "[\"/diorama-hello\"]",
                "localhost/diorama-hello:latest",
                "600"
            ]
        );
        let minimal = create_arguments(&ContainerSpec {
            name: "n".to_string(),
            image: "img".to_string(),
            ..ContainerSpec::default()
        })
        .unwrap();
        assert_eq!(minimal, ["create", "--name", "n", "--pull", "never", "img"]);

        let spec_with_mounts_and_res = ContainerSpec {
            name: "full".to_string(),
            image: "img".to_string(),
            mounts: vec![
                MountSpec {
                    container_path: "/data".to_string(),
                    host_path: "/var/data".to_string(),
                    readonly: false,
                },
                MountSpec {
                    container_path: "/etc/config".to_string(),
                    host_path: "/var/config".to_string(),
                    readonly: true,
                },
            ],
            resources: Some(ResourceSpec {
                cpu_shares: Some(512),
                cpu_quota: Some(25_000),
                cpu_period: Some(100_000),
                cpuset_cpus: Some("0-1".to_string()),
                memory_limit_in_bytes: Some(104_857_600),
            }),
            ..ContainerSpec::default()
        };
        assert_eq!(
            create_arguments(&spec_with_mounts_and_res).unwrap(),
            [
                "create",
                "--name",
                "full",
                "--pull",
                "never",
                "-v",
                "/var/data:/data",
                "-v",
                "/var/config:/etc/config:ro",
                "--cpu-shares",
                "512",
                "--cpu-quota",
                "25000",
                "--cpu-period",
                "100000",
                "--cpuset-cpus",
                "0-1",
                "--memory",
                "104857600",
                "img"
            ]
        );
    }

    #[test]
    fn pod_create_arguments_carries_ports_and_labels() {
        let ports = vec![
            PortMappingSpec {
                protocol: "tcp".to_string(),
                container_port: 80,
                host_port: 8080,
                host_ip: Some("127.0.0.1".to_string()),
            },
            PortMappingSpec {
                protocol: "udp".to_string(),
                container_port: 53,
                host_port: 0,
                host_ip: None,
            },
        ];
        let labels = BTreeMap::from([("io.kubernetes.pod.name".to_string(), "p1".to_string())]);
        let args = pod_create_arguments("pod-1", &labels, &ports);
        assert_eq!(
            args,
            [
                "pod",
                "create",
                "--name",
                "pod-1",
                "-p",
                "127.0.0.1:8080:80/tcp",
                "-p",
                "53/udp",
                "--label",
                "io.kubernetes.pod.name=p1"
            ]
        );
    }

    #[test]
    fn log_arguments_carry_tail_timestamps_and_since() {
        let options = LogOptions {
            follow: true,
            tail_lines: Some(5),
            timestamps: true,
            since_seconds: Some(30),
            previous: false,
        };
        assert_eq!(
            log_arguments("abc", &options),
            [
                "logs",
                "--follow",
                "--tail",
                "5",
                "--timestamps",
                "--since",
                "30s",
                "abc"
            ]
        );
        assert_eq!(
            log_arguments("abc", &LogOptions::default()),
            ["logs", "abc"]
        );
    }

    #[test]
    fn ps_output_maps_running_and_exited_containers() {
        let stdout = r#"[
          {"Id":"abc123","Names":["k8s_hello_hello_default_u1_0"],"Pod":"pod1","Image":"localhost/diorama-hello:latest","ImageID":"e247","Labels":{"io.kubernetes.container.name":"hello","io.kubernetes.pod.uid":"u1"},"State":"running","ExitCode":0,"Exited":false,"StartedAt":1791146364,"ExitedAt":-62135596800,"Created":1791146360},
          {"Id":"def456","Image":"img","ImageID":"sha256:i2","Labels":{"io.kubernetes.container.name":"side"},"State":"exited","ExitCode":3,"Exited":true,"StartedAt":1791146364,"ExitedAt":1791146370},
          {"Id":"ghi789","State":"created"},
          {"Id":"infra1","Names":["07c3f46e7825-infra"],"Pod":"pod1","State":"running","IsInfra":true}
        ]"#;
        let entries = parse_ps_output(stdout).unwrap();
        assert_eq!(entries.len(), 4);
        assert!(entries[3].is_infra && !entries[0].is_infra);
        let running = entries[0].clone().into_summary();
        assert_eq!(running.id, "abc123");
        assert_eq!(running.name, "k8s_hello_hello_default_u1_0");
        assert_eq!(running.pod_id, "pod1");
        assert_eq!(running.image_id, "sha256:e247");
        assert_eq!(running.created, Some(1_791_146_360));
        assert_eq!(
            running.state,
            ContainerState::Running {
                started_at: Some(1_791_146_364)
            }
        );
        let exited = entries[1].clone().into_summary();
        assert_eq!(exited.image_id, "sha256:i2");
        assert_eq!(
            exited.state,
            ContainerState::Exited {
                exit_code: 3,
                started_at: Some(1_791_146_364),
                finished_at: Some(1_791_146_370),
            }
        );
        assert_eq!(
            entries[2].clone().into_summary().state,
            ContainerState::Idle("created".to_string())
        );
        assert!(parse_ps_output("").unwrap().is_empty());
        assert!(parse_ps_output("[]").unwrap().is_empty());
        assert!(parse_ps_output("not json").is_err());
    }

    #[test]
    fn pod_ps_output_maps_running_and_stopped_pods() {
        let stdout = r#"[
          {"Id":"c8c6","Name":"k8s_POD_hello_default_u1_0","Status":"Running","Labels":{"io.kubernetes.pod.uid":"u1"},"InfraId":"1962","Created":"2026-10-05T06:33:28.178518557-04:00","Containers":[]},
          {"Id":"d9d7","Name":"k8s_POD_old_default_u0_0","Status":"Exited","Labels":{}},
          {"Id":"e0e8","Name":"degraded","Status":"Degraded","Labels":{}}
        ]"#;
        let pods: Vec<PodSummary> = parse_pod_ps_output(stdout)
            .unwrap()
            .into_iter()
            .map(PodPsEntry::into_summary)
            .collect();
        assert_eq!(pods.len(), 3);
        assert!(pods[0].running);
        assert_eq!(pods[0].labels["io.kubernetes.pod.uid"], "u1");
        assert!(!pods[1].running);
        assert!(pods[2].running);
    }

    #[test]
    fn version_is_parsed_from_podman_output() {
        assert_eq!(
            parse_version("podman version 6.0.2\n").as_deref(),
            Some("6.0.2")
        );
        assert_eq!(parse_version(""), None);
        assert_eq!(PodmanEngine::new("/x/podman").version(), None);
        assert_eq!(
            PodmanEngine::new("/x/podman")
                .with_version("6.0.2")
                .version()
                .as_deref(),
            Some("6.0.2")
        );
        assert_eq!(PodmanEngine::new("/x/podman").name(), "podman");
        assert_eq!(prefix_sha("abc"), "sha256:abc");
        assert_eq!(prefix_sha("sha256:abc"), "sha256:abc");
    }

    #[test]
    fn null_labels_deserialized_as_empty_map() {
        let ps_stdout = r#"[{"Id":"c1","Labels":null}]"#;
        let entries = parse_ps_output(ps_stdout).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].labels.is_empty());

        let pod_ps_stdout = r#"[{"Id":"p1","Labels":null}]"#;
        let pods = parse_pod_ps_output(pod_ps_stdout).unwrap();
        assert_eq!(pods.len(), 1);
        assert!(pods[0].labels.is_empty());
    }
}
