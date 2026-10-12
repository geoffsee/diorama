use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use diorama_apiserver::{
    ApiserverError, ApiserverService, KubernetesApiClient, PodLogOptions, PodLogReader,
};
use serde_json::Value;

use crate::config::KubeletConfigOptions;
use crate::container::ContainerEnvironment;
use crate::error::KubeletError;
use crate::health::KubeletHealthReport;
use crate::reconciler::{PodReconciler, resolve_container};
use crate::registration::NodeRegistration;
use crate::workload::{
    CpuManager, ExecResult, LogOptions, ReconcileReport, RuntimeProvider, WorkloadRestartReport,
};

/// Kubelet service orchestrating node lifecycle, registration, and workload execution.
#[derive(Clone, Debug)]
pub struct KubeletService {
    options: KubeletConfigOptions,
    apiserver: Arc<ApiserverService>,
    runtime: Arc<dyn RuntimeProvider>,
    running: Arc<AtomicBool>,
    registration: NodeRegistration,
    reconciler: PodReconciler,
    container_env: ContainerEnvironment,
}

impl KubeletService {
    pub fn new(
        options: KubeletConfigOptions,
        apiserver: Arc<ApiserverService>,
        runtime: Arc<dyn RuntimeProvider>,
    ) -> Self {
        let client = Arc::new(apiserver.node_client(&options.node_name));
        let registration = NodeRegistration::new(
            client.clone(),
            options.clone(),
            format!(
                "{}://{}",
                runtime.provider_name(),
                runtime.runtime_version()
            ),
        );
        let cpu_manager = Arc::new(CpuManager::from_options(&options));
        let reconciler = PodReconciler::new(
            client,
            runtime.clone(),
            &options.node_name,
            &options.node_ip,
        )
        .with_cpu_manager(cpu_manager)
        .with_root_dir(options.root_dir.clone())
        .with_apiserver(apiserver.clone());

        Self {
            options,
            apiserver,
            runtime,
            running: Arc::new(AtomicBool::new(false)),
            registration,
            reconciler,
            container_env: ContainerEnvironment::default(),
        }
    }

    #[must_use]
    pub fn with_container_environment(mut self, env: ContainerEnvironment) -> Self {
        self.container_env = env;
        self
    }

    #[must_use]
    pub fn container_environment(&self) -> &ContainerEnvironment {
        &self.container_env
    }

    #[must_use]
    pub fn options(&self) -> &KubeletConfigOptions {
        &self.options
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn is_snat_ready(&self) -> bool {
        self.container_env.is_snat_ready()
    }

    #[must_use]
    pub fn client(&self) -> KubernetesApiClient {
        self.apiserver.node_client(&self.options.node_name)
    }

    #[must_use]
    pub fn reconciler(&self) -> &PodReconciler {
        &self.reconciler
    }

    #[must_use]
    pub fn registration(&self) -> &NodeRegistration {
        &self.registration
    }

    pub async fn get_container_logs(
        &self,
        pod_id: &str,
        container_name: &str,
        tail_lines: Option<usize>,
    ) -> Result<String, KubeletError> {
        self.reconciler
            .get_container_logs(pod_id, container_name, tail_lines)
            .await
    }

    pub async fn exec_in_container(
        &self,
        pod_id: &str,
        container_name: &str,
        cmd: &[String],
    ) -> Result<ExecResult, KubeletError> {
        self.reconciler
            .exec_in_container(pod_id, container_name, cmd)
            .await
    }

    #[must_use]
    pub fn get_pod_volume_dir(
        &self,
        pod_uid_or_name: &str,
        plugin_name: &str,
        volume_name: &str,
    ) -> std::path::PathBuf {
        self.reconciler
            .get_pod_volume_dir(pod_uid_or_name, plugin_name, volume_name)
    }

    /// Validates all credentials, CRI runtime endpoints, and API server reachability.
    ///
    /// Identifies the responsible component specifically:
    /// - `KubeletError::MissingCredential` / `AuthenticationFailed` for PKI/auth failures
    /// - `KubeletError::RuntimeUnavailable` for CRI endpoint connectivity failures
    /// - `KubeletError::ApiserverUnavailable` for API server outages
    pub async fn check_prerequisites(&self) -> Result<(), KubeletError> {
        // 1. Verify credential file paths
        if !self.options.kubeconfig.exists() {
            return Err(KubeletError::MissingCredential {
                path: self.options.kubeconfig.clone(),
                component: "kubeconfig",
            });
        }

        if !self.options.ca_file.exists() {
            return Err(KubeletError::MissingCredential {
                path: self.options.ca_file.clone(),
                component: "root-ca",
            });
        }

        if !self.options.cert_file.exists() {
            return Err(KubeletError::MissingCredential {
                path: self.options.cert_file.clone(),
                component: "client-cert",
            });
        }

        if !self.options.key_file.exists() {
            return Err(KubeletError::MissingCredential {
                path: self.options.key_file.clone(),
                component: "client-key",
            });
        }

        // Validate kubeconfig content and user identity
        let kubeconfig_content =
            std::fs::read_to_string(&self.options.kubeconfig).map_err(|e| {
                KubeletError::InvalidConfiguration {
                    field: "kubeconfig".to_string(),
                    reason: format!("failed to read kubeconfig: {e}"),
                }
            })?;

        self.validate_kubeconfig_client_cert(&kubeconfig_content)?;

        // 2. Validate CRI runtime endpoint
        let endpoint_str = &self.options.runtime_endpoint;
        let socket_path = endpoint_str.trim_start_matches("unix://");
        let path = Path::new(socket_path);
        if self.runtime.requires_socket() && !path.exists() {
            return Err(KubeletError::RuntimeUnavailable {
                endpoint: endpoint_str.clone(),
                reason: format!("CRI runtime socket does not exist at {}", path.display()),
            });
        }

        self.runtime.check_available().await?;
        self.registration.set_runtime_version(format!(
            "{}://{}",
            self.runtime.provider_name(),
            self.runtime.runtime_version()
        ));

        // 3. Validate API server communication and node authorization
        let client = self.client();
        client
            .list_nodes()
            .await
            .map_err(|e| KubeletError::ApiserverUnavailable {
                reason: format!("failed to list nodes with node identity: {e}"),
            })?;

        // 4. Validate upstream resource defaults preservation
        self.options.validate_upstream_resource_defaults()?;

        Ok(())
    }

    /// Starts the Kubelet service, writes its config, and registers the node.
    pub async fn start(&self) -> Result<(), KubeletError> {
        self.check_prerequisites().await?;
        if self.options.container_mode {
            let _ = self.container_env.prepare_mounts()?;
            let _ = self.container_env.prepare_cgroups(std::process::id())?;
        }
        if self.options.disable_ipv6 {
            let _ = self.container_env.disable_ipv6()?;
        }
        if let Some(cidr) = self.container_env.pod_cidr().map(ToString::to_string) {
            let _ = self.container_env.prepare_pod_egress(&cidr)?;
        }
        let invalidated = self.options.write_kubelet_config_file()?;
        if invalidated {
            self.reconciler.cpu_manager().reset();
        }
        self.reconciler.mark_checkpoint_invalidated(invalidated);
        self.registration.register_or_update().await?;
        self.registration.update_lease().await?;
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Log reader for the apiserver's pod log subresource.
    #[must_use]
    pub fn log_source(&self) -> KubeletLogSource {
        KubeletLogSource {
            node_name: self.options.node_name.clone(),
            runtime: self.runtime.clone(),
        }
    }

    /// One pass of the kubelet loop: bind, sync and clean up every pod in the cluster.
    pub async fn reconcile_once(&self) -> Result<ReconcileReport, KubeletError> {
        self.reconciler.reconcile_all().await
    }

    /// Renews the node lease and re-asserts node status.
    pub async fn heartbeat(&self) -> Result<(), KubeletError> {
        self.registration.register_or_update().await?;
        self.registration.update_lease().await?;
        Ok(())
    }

    /// Reports any surviving external-runtime containers that require restart after a CPU manager settings change.
    pub async fn report_workload_restart_needs(
        &self,
        namespace: &str,
    ) -> Result<Vec<WorkloadRestartReport>, KubeletError> {
        self.reconciler
            .report_workload_restart_needs(namespace)
            .await
    }

    /// Checks the health and readiness of the Kubelet service.
    pub async fn check_readiness(&self) -> Result<KubeletHealthReport, KubeletError> {
        if !self.is_running() {
            return Ok(KubeletHealthReport::new_unhealthy(
                &self.options.node_name,
                "kubelet service is not running",
            ));
        }

        // Verify API server connectivity
        let client = self.client();
        let node_doc = match client.get_node(&self.options.node_name).await {
            Ok(doc) => doc,
            Err(e) => {
                return Ok(KubeletHealthReport::new_unhealthy(
                    &self.options.node_name,
                    format!("API server communication failed: {e}"),
                ));
            },
        };

        // Verify node Ready condition
        let mut is_ready = false;
        if let Some(conditions) = node_doc
            .get("status")
            .and_then(|s| s.get("conditions"))
            .and_then(serde_json::Value::as_array)
        {
            for cond in conditions {
                if cond.get("type").and_then(serde_json::Value::as_str) == Some("Ready")
                    && cond.get("status").and_then(serde_json::Value::as_str) == Some("True")
                {
                    is_ready = true;
                    break;
                }
            }
        }

        Ok(KubeletHealthReport::new_healthy(
            &self.options.node_name,
            is_ready,
            &self.options.runtime_endpoint,
            self.runtime.provider_name(),
            &self.options.cgroup_driver,
            0,
        ))
    }

    fn validate_kubeconfig_client_cert(
        &self,
        kubeconfig_content: &str,
    ) -> Result<(), KubeletError> {
        let expected_node_user = format!("system:node:{}", self.options.node_name);
        let cert_pem = if let Some(idx) = kubeconfig_content.find("client-certificate-data:") {
            let after = &kubeconfig_content[idx + "client-certificate-data:".len()..];
            let b64_token = after.split_whitespace().next().unwrap_or("");
            let decoded = diorama_pki::base64_decode(b64_token).map_err(|_| {
                KubeletError::AuthenticationFailed {
                    reason: "failed to decode client-certificate-data in kubeconfig".to_string(),
                }
            })?;
            String::from_utf8(decoded).map_err(|_| KubeletError::AuthenticationFailed {
                reason: "client-certificate-data is not valid UTF-8 PEM".to_string(),
            })?
        } else if let Some(idx) = kubeconfig_content.find("client-certificate:") {
            let after = &kubeconfig_content[idx + "client-certificate:".len()..];
            let path_str = after.lines().next().unwrap_or("").trim();
            let cert_path = Path::new(path_str);
            let resolved_path = if cert_path.is_absolute() {
                cert_path.to_path_buf()
            } else {
                self.options
                    .kubeconfig
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(cert_path)
            };
            std::fs::read_to_string(&resolved_path).map_err(|e| {
                KubeletError::AuthenticationFailed {
                    reason: format!(
                        "failed to read client-certificate file {}: {e}",
                        resolved_path.display()
                    ),
                }
            })?
        } else {
            return Err(KubeletError::AuthenticationFailed {
                reason: "kubeconfig missing client certificate credentials".to_string(),
            });
        };

        let ca_pem = std::fs::read_to_string(&self.options.ca_file).map_err(|e| {
            KubeletError::InvalidConfiguration {
                field: "ca_file".to_string(),
                reason: format!("failed to read ca_file: {e}"),
            }
        })?;

        let identity = diorama_pki::verify_certificate_chain(&cert_pem, &ca_pem).map_err(|e| {
            KubeletError::AuthenticationFailed {
                reason: format!("kubeconfig client certificate verification failed: {e}"),
            }
        })?;

        if identity.common_name != expected_node_user {
            return Err(KubeletError::AuthenticationFailed {
                reason: format!(
                    "kubeconfig client certificate CN '{}' does not match expected '{}'",
                    identity.common_name, expected_node_user
                ),
            });
        }

        Ok(())
    }

    /// Stops the Kubelet service.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Serves the pod log subresource for pods this kubelet runs.
///
/// It holds only the runtime provider and node name, never the apiserver, so
/// registering it with [`ApiserverService::set_pod_log_reader`] cannot create
/// a reference cycle that would keep the datastore lock alive after shutdown.
#[derive(Clone, Debug)]
pub struct KubeletLogSource {
    node_name: String,
    runtime: Arc<dyn RuntimeProvider>,
}

#[async_trait]
impl PodLogReader for KubeletLogSource {
    async fn read_pod_log(
        &self,
        pod: &Value,
        options: &PodLogOptions,
    ) -> Result<String, ApiserverError> {
        let name = pod
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let assigned = pod.pointer("/spec/nodeName").and_then(Value::as_str);
        if assigned != Some(self.node_name.as_str()) {
            return Err(ApiserverError::BadRequest {
                message: format!("pod {name} is not assigned to node {}", self.node_name),
            });
        }
        let uid = pod
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::BadRequest {
                message: format!("pod {name} has no uid"),
            })?;
        let container = match &options.container {
            Some(container) => container.clone(),
            None => pod
                .pointer("/spec/containers/0/name")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiserverError::BadRequest {
                    message: format!("pod {name} has no containers"),
                })?
                .to_string(),
        };
        // A container that has never run has no log. One waiting between restart
        // attempts still has its last attempt's output, as upstream serves it.
        let status = pod
            .pointer("/status/containerStatuses")
            .and_then(Value::as_array)
            .and_then(|statuses| {
                statuses
                    .iter()
                    .find(|s| s["name"].as_str() == Some(container.as_str()))
            });
        let waiting = status
            .and_then(|status| status.pointer("/state/waiting/reason"))
            .and_then(Value::as_str);
        let has_previous = status
            .and_then(|status| status.pointer("/lastState/terminated"))
            .is_some();
        if let Some(reason) = waiting.filter(|_| !has_previous) {
            return Err(ApiserverError::BadRequest {
                message: format!(
                    "container \"{container}\" in pod \"{name}\" is waiting to start: {reason}"
                ),
            });
        }
        let log_options = LogOptions {
            tail_lines: options.tail_lines,
            timestamps: options.timestamps,
            since_seconds: options.since_seconds,
            previous: options.previous,
            follow: options.follow,
        };
        let id = resolve_container(self.runtime.as_ref(), uid, &container, options.previous)
            .await
            .map_err(|e| ApiserverError::BadRequest {
                message: format!("{e}"),
            })?;
        self.runtime
            .container_logs(&id, &log_options)
            .await
            .map_err(|e| ApiserverError::Internal {
                reason: format!("kubelet could not read logs for {name}/{container}: {e}"),
            })
    }
}
