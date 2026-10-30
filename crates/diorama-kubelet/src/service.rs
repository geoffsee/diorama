use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use bytes::Buf;
use diorama_apiserver::{
    ApiserverError, ApiserverService, ExecStreamInput, ExecStreamOutput, KubernetesApiClient,
    PodExec, PodExecResult, PodLogOptions, PodLogReader, RemoteExecRequest, RemoteExecResponse,
    RemoteExecStreamHeader, RemoteLogRequest, RemoteLogResponse, RemoteLogStreamChunk,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio_quiche::http3::driver::{
    InboundFrame, IncomingH3Headers, OutboundFrame, ServerH3Driver, ServerH3Event,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quiche::h3::{Header, NameValue};
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::{ConnectionParams, ServerH3Controller, listen};

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
    apiserver: Option<Arc<ApiserverService>>,
    client: Arc<KubernetesApiClient>,
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
            client.clone(),
            runtime.clone(),
            &options.node_name,
            &options.node_ip,
        )
        .with_cluster_dns(options.cluster_dns.clone())
        .with_cluster_domain(options.cluster_domain.clone())
        .with_cpu_manager(cpu_manager)
        .with_root_dir(options.root_dir.clone())
        .with_apiserver(apiserver.clone());

        Self {
            options,
            apiserver: Some(apiserver),
            client,
            runtime,
            running: Arc::new(AtomicBool::new(false)),
            registration,
            reconciler,
            container_env: ContainerEnvironment::default(),
        }
    }

    pub fn from_client(
        options: KubeletConfigOptions,
        client: Arc<KubernetesApiClient>,
        runtime: Arc<dyn RuntimeProvider>,
    ) -> Self {
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
            client.clone(),
            runtime.clone(),
            &options.node_name,
            &options.node_ip,
        )
        .with_cluster_dns(options.cluster_dns.clone())
        .with_cluster_domain(options.cluster_domain.clone())
        .with_cpu_manager(cpu_manager)
        .with_root_dir(options.root_dir.clone())
        .with_multi_node(true);

        Self {
            options,
            apiserver: None,
            client,
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
    pub fn with_multi_node(mut self, multi_node: bool) -> Self {
        self.reconciler = self.reconciler.with_multi_node(multi_node);
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
        self.apiserver.as_ref().map_or_else(
            || (*self.client).clone(),
            |api| api.node_client(&self.options.node_name),
        )
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

    /// Exec target for the apiserver's pod exec subresource.
    #[must_use]
    pub fn exec_source(&self) -> KubeletExecSource {
        KubeletExecSource {
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

    /// Starts a `tokio-quiche` HTTP/3 listener (`ServerH3Driver`) serving remote
    /// `/pods/log` and `/pods/exec` requests from peer API servers.
    pub async fn start_quic_proxy_server(
        &self,
        listen_addr: SocketAddr,
        cert_file: PathBuf,
        key_file: PathBuf,
    ) -> Result<SocketAddr, KubeletError> {
        let socket = UdpSocket::bind(listen_addr).await?;
        let local_addr = socket.local_addr()?;

        let cert_str = cert_file.to_string_lossy().into_owned();
        let key_str = key_file.to_string_lossy().into_owned();
        let mut quic_settings = QuicSettings::default();
        quic_settings.max_idle_timeout = Some(std::time::Duration::from_secs(30));

        let params = ConnectionParams::new_server(
            quic_settings,
            TlsCertificatePaths {
                cert: &cert_str,
                private_key: &key_str,
                kind: CertificateKind::X509,
            },
            Hooks::default(),
        );

        let mut listeners = listen([socket], params, DefaultMetrics).map_err(|e| {
            KubeletError::InvalidConfiguration {
                field: "quic_proxy".to_string(),
                reason: format!("tokio-quiche listen failed: {e}"),
            }
        })?;
        let mut stream = listeners
            .pop()
            .ok_or_else(|| KubeletError::InvalidConfiguration {
                field: "quic_proxy".to_string(),
                reason: "missing QUIC listener stream".to_string(),
            })?;

        let log_source = self.log_source();
        let exec_source = self.exec_source();
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            while let Some(conn_res) = stream.next().await {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(conn) = conn_res {
                    let (driver, controller) = ServerH3Driver::new(Http3Settings::default());
                    let quic_conn = conn.start(driver);
                    tokio::spawn(handle_kubelet_h3_connection(
                        controller,
                        quic_conn,
                        log_source.clone(),
                        exec_source.clone(),
                    ));
                }
            }
        });

        Ok(local_addr)
    }
}

async fn handle_kubelet_h3_connection<T: Send + 'static>(
    mut controller: ServerH3Controller,
    quic_conn: T,
    log_source: KubeletLogSource,
    exec_source: KubeletExecSource,
) {
    let _keep_alive = quic_conn;
    while let Some(event) = controller.event_receiver_mut().recv().await {
        if let ServerH3Event::Headers {
            incoming_headers, ..
        } = event
        {
            tokio::spawn(handle_kubelet_h3_request(
                incoming_headers,
                log_source.clone(),
                exec_source.clone(),
            ));
        }
    }
}

async fn handle_kubelet_h3_request(
    headers: IncomingH3Headers,
    log_source: KubeletLogSource,
    exec_source: KubeletExecSource,
) {
    let IncomingH3Headers {
        headers: req_headers,
        mut send,
        mut recv,
        ..
    } = headers;

    let path = req_headers
        .iter()
        .find(|h| h.name() == b":path")
        .map(|h| String::from_utf8_lossy(h.value()).into_owned())
        .unwrap_or_default();

    if path == "/pods/log/stream" {
        handle_remote_log_stream(send, recv, log_source).await;
        return;
    }
    if path == "/pods/exec/stream" {
        handle_remote_exec_stream(send, recv, exec_source).await;
        return;
    }

    let mut body = Vec::new();
    while let Some(InboundFrame::Body(mut chunk, fin)) = recv.recv().await {
        let len = chunk.remaining();
        body.extend_from_slice(&chunk.copy_to_bytes(len));
        if fin {
            break;
        }
    }

    let response_bytes = match path.as_str() {
        "/pods/log" => handle_remote_log_rpc(&body, &log_source).await,
        "/pods/exec" => handle_remote_exec_rpc(&body, &exec_source).await,
        _ => Vec::new(),
    };

    let status = if response_bytes.is_empty() {
        b"404"
    } else {
        b"200"
    };
    let _ = send
        .send(OutboundFrame::Headers(
            vec![Header::new(b":status", status)],
            None,
        ))
        .await;
    let _ = send
        .send(OutboundFrame::Body(response_bytes.into(), true))
        .await;
}

async fn handle_remote_log_stream(
    mut send: tokio_quiche::http3::driver::OutboundFrameSender,
    mut recv: tokio_quiche::http3::driver::InboundFrameStream,
    log_source: KubeletLogSource,
) {
    let mut body = Vec::new();
    while let Some(InboundFrame::Body(mut chunk, fin)) = recv.recv().await {
        let len = chunk.remaining();
        body.extend_from_slice(&chunk.copy_to_bytes(len));
        if fin {
            break;
        }
    }

    if send
        .send(OutboundFrame::Headers(
            vec![Header::new(b":status", b"200")],
            None,
        ))
        .await
        .is_err()
    {
        return;
    }

    let Ok(req) = serde_json::from_slice::<RemoteLogRequest>(&body) else {
        let _ = send_log_stream_chunk(
            &mut send,
            &RemoteLogStreamChunk::BadRequest("invalid RemoteLogRequest".into()),
            true,
        )
        .await;
        return;
    };
    let options = PodLogOptions {
        container: req.container,
        tail_lines: req.tail_lines,
        timestamps: req.timestamps,
        since_seconds: req.since_seconds,
        previous: req.previous,
        follow: req.follow,
        limit_bytes: req.limit_bytes,
    };

    let mut rx = match log_source.stream_pod_log(&req.pod, &options).await {
        Ok(rx) => rx,
        Err(ApiserverError::BadRequest { message }) => {
            let _ =
                send_log_stream_chunk(&mut send, &RemoteLogStreamChunk::BadRequest(message), true)
                    .await;
            return;
        },
        Err(err) => {
            let _ = send_log_stream_chunk(
                &mut send,
                &RemoteLogStreamChunk::Internal(err.to_string()),
                true,
            )
            .await;
            return;
        },
    };

    while let Some(item) = rx.recv().await {
        let chunk = match item {
            Ok(s) => RemoteLogStreamChunk::Chunk(s),
            Err(ApiserverError::BadRequest { message }) => {
                RemoteLogStreamChunk::BadRequest(message)
            },
            Err(e) => RemoteLogStreamChunk::Internal(e.to_string()),
        };
        if send_log_stream_chunk(&mut send, &chunk, false)
            .await
            .is_err()
        {
            return;
        }
    }
    let _ = send_log_stream_chunk(&mut send, &RemoteLogStreamChunk::Eof, true).await;
}

async fn send_log_stream_chunk(
    send: &mut tokio_quiche::http3::driver::OutboundFrameSender,
    chunk: &RemoteLogStreamChunk,
    fin: bool,
) -> Result<(), ()> {
    let mut line = serde_json::to_vec(chunk).map_err(|_| ())?;
    line.push(b'\n');
    send.send(OutboundFrame::Body(line.into(), fin))
        .await
        .map_err(|_| ())
}

async fn handle_remote_exec_stream(
    mut send: tokio_quiche::http3::driver::OutboundFrameSender,
    mut recv: tokio_quiche::http3::driver::InboundFrameStream,
    exec_source: KubeletExecSource,
) {
    if send
        .send(OutboundFrame::Headers(
            vec![Header::new(b":status", b"200")],
            None,
        ))
        .await
        .is_err()
    {
        return;
    }

    let mut line_buf = Vec::new();
    let header: RemoteExecStreamHeader = loop {
        if let Some(pos) = line_buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = line_buf.drain(..=pos).collect();
            let Ok(hdr) = serde_json::from_slice(&line) else {
                return;
            };
            break hdr;
        }
        let Some(InboundFrame::Body(mut chunk, _fin)) = recv.recv().await else {
            return;
        };
        let len = chunk.remaining();
        line_buf.extend_from_slice(&chunk.copy_to_bytes(len));
    };

    let (in_tx, mut out_rx) = match exec_source
        .stream_exec_in_pod(&header.pod, &header.container, &header.command, header.tty)
        .await
    {
        Ok(pair) => pair,
        Err(err) => {
            let _ =
                send_exec_stream_output(&mut send, &ExecStreamOutput::Error(err.to_string()), true)
                    .await;
            return;
        },
    };

    tokio::spawn(pump_exec_inbound_frames(recv, line_buf, in_tx));

    while let Some(out) = out_rx.recv().await {
        let is_exit = matches!(out, ExecStreamOutput::Exit(_));
        if send_exec_stream_output(&mut send, &out, is_exit)
            .await
            .is_err()
            || is_exit
        {
            break;
        }
    }
}

async fn pump_exec_inbound_frames(
    mut recv: tokio_quiche::http3::driver::InboundFrameStream,
    mut line_buf: Vec<u8>,
    in_tx: tokio::sync::mpsc::Sender<ExecStreamInput>,
) {
    loop {
        while let Some(pos) = line_buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = line_buf.drain(..=pos).collect();
            let Ok(input) = serde_json::from_slice::<ExecStreamInput>(&line) else {
                continue;
            };
            let is_close = matches!(input, ExecStreamInput::Close);
            if in_tx.send(input).await.is_err() || is_close {
                return;
            }
        }
        let Some(InboundFrame::Body(mut chunk, fin)) = recv.recv().await else {
            break;
        };
        let len = chunk.remaining();
        line_buf.extend_from_slice(&chunk.copy_to_bytes(len));
        if fin && !line_buf.contains(&b'\n') {
            break;
        }
    }
    let _ = in_tx.send(ExecStreamInput::Close).await;
}

async fn send_exec_stream_output(
    send: &mut tokio_quiche::http3::driver::OutboundFrameSender,
    out: &ExecStreamOutput,
    fin: bool,
) -> Result<(), ()> {
    let mut line = serde_json::to_vec(out).map_err(|_| ())?;
    line.push(b'\n');
    send.send(OutboundFrame::Body(line.into(), fin))
        .await
        .map_err(|_| ())
}

async fn handle_remote_log_rpc(body: &[u8], log_source: &KubeletLogSource) -> Vec<u8> {
    let resp = match serde_json::from_slice::<RemoteLogRequest>(body) {
        Ok(req) => {
            let options = PodLogOptions {
                container: req.container,
                tail_lines: req.tail_lines,
                timestamps: req.timestamps,
                since_seconds: req.since_seconds,
                previous: req.previous,
                follow: req.follow,
                limit_bytes: req.limit_bytes,
            };
            match log_source.read_pod_log(&req.pod, &options).await {
                Ok(logs) => RemoteLogResponse::Ok(logs),
                Err(ApiserverError::BadRequest { message }) => {
                    RemoteLogResponse::BadRequest(message)
                },
                Err(e) => RemoteLogResponse::Internal(e.to_string()),
            }
        },
        Err(e) => RemoteLogResponse::BadRequest(e.to_string()),
    };
    serde_json::to_vec(&resp).unwrap_or_default()
}

async fn handle_remote_exec_rpc(body: &[u8], exec_source: &KubeletExecSource) -> Vec<u8> {
    let resp = match serde_json::from_slice::<RemoteExecRequest>(body) {
        Ok(req) => match exec_source
            .exec_in_pod(&req.pod, &req.container, &req.command)
            .await
        {
            Ok(res) => RemoteExecResponse::Ok {
                exit_code: res.exit_code,
                stdout: res.stdout,
                stderr: res.stderr,
            },
            Err(ApiserverError::BadRequest { message }) => RemoteExecResponse::BadRequest(message),
            Err(e) => RemoteExecResponse::Internal(e.to_string()),
        },
        Err(e) => RemoteExecResponse::BadRequest(e.to_string()),
    };
    serde_json::to_vec(&resp).unwrap_or_default()
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
        let companion_node = crate::config::companion_node_name(&self.node_name);
        if assigned != Some(self.node_name.as_str()) && assigned != Some(companion_node.as_str()) {
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

    async fn stream_pod_log(
        &self,
        pod: &Value,
        options: &PodLogOptions,
    ) -> Result<tokio::sync::mpsc::Receiver<Result<String, ApiserverError>>, ApiserverError> {
        let initial = self.read_pod_log(pod, options).await?;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let source = self.clone();
        let pod_clone = pod.clone();
        let opts_clone = options.clone();
        tokio::spawn(async move {
            let mut sent_len = initial.len();
            for line in initial.split_inclusive('\n') {
                if tx.send(Ok(line.to_string())).await.is_err() {
                    return;
                }
            }
            if !opts_clone.follow {
                return;
            }
            for _ in 0..40 {
                if tx.is_closed() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let Ok(latest) = source.read_pod_log(&pod_clone, &opts_clone).await else {
                    break;
                };
                if latest.len() > sent_len {
                    let delta = &latest[sent_len..];
                    sent_len = latest.len();
                    for line in delta.split_inclusive('\n') {
                        if tx.send(Ok(line.to_string())).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
        Ok(rx)
    }
}

/// Serves the pod exec subresource for pods this kubelet runs.
///
/// Like [`KubeletLogSource`] it holds only the runtime provider and node name,
/// never the apiserver, so registering it cannot create a reference cycle.
#[derive(Clone, Debug)]
pub struct KubeletExecSource {
    node_name: String,
    runtime: Arc<dyn RuntimeProvider>,
}

#[async_trait]
impl PodExec for KubeletExecSource {
    async fn exec_in_pod(
        &self,
        pod: &Value,
        container: &str,
        command: &[String],
    ) -> Result<PodExecResult, ApiserverError> {
        let name = pod
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let assigned = pod.pointer("/spec/nodeName").and_then(Value::as_str);
        let companion_node = crate::config::companion_node_name(&self.node_name);
        if assigned != Some(self.node_name.as_str()) && assigned != Some(companion_node.as_str()) {
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
        if command.is_empty() {
            return Err(ApiserverError::BadRequest {
                message: "exec requires a command".to_string(),
            });
        }
        let id_res = resolve_container(self.runtime.as_ref(), uid, container, false).await;
        let id = match id_res {
            Ok(id) => id,
            Err(e) => {
                let is_ephemeral = pod
                    .pointer("/spec/ephemeralContainers")
                    .and_then(Value::as_array)
                    .is_some_and(|arr| {
                        arr.iter()
                            .any(|c| c.get("name").and_then(Value::as_str) == Some(container))
                    });
                if is_ephemeral {
                    let mut fallback = None;
                    if let Some(spec_containers) =
                        pod.pointer("/spec/containers").and_then(Value::as_array)
                    {
                        for c in spec_containers {
                            if let Some(c_name) = c.get("name").and_then(Value::as_str)
                                && let Ok(cid) =
                                    resolve_container(self.runtime.as_ref(), uid, c_name, false)
                                        .await
                            {
                                fallback = Some(cid);
                                break;
                            }
                        }
                    }
                    if let Some(cid) = fallback {
                        cid
                    } else {
                        return Err(ApiserverError::BadRequest {
                            message: format!("{e}"),
                        });
                    }
                } else {
                    return Err(ApiserverError::BadRequest {
                        message: format!("{e}"),
                    });
                }
            },
        };
        // Interactive exec is emulated with one synchronous CRI call; the
        // gateway replays the captured output on the websocket channels.
        let output = self
            .runtime
            .exec_sync(&id, command, 30)
            .await
            .map_err(|e| ApiserverError::Internal {
                reason: format!("kubelet could not exec in {name}/{container}: {e}"),
            })?;
        Ok(PodExecResult {
            exit_code: output.exit_code,
            stdout: output.stdout.into_bytes(),
            stderr: output.stderr.into_bytes(),
        })
    }

    async fn stream_exec_in_pod(
        &self,
        pod: &Value,
        container: &str,
        command: &[String],
        tty: bool,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<ExecStreamInput>,
            tokio::sync::mpsc::Receiver<ExecStreamOutput>,
        ),
        ApiserverError,
    > {
        if command.is_empty() {
            return Err(ApiserverError::BadRequest {
                message: "exec requires a command".to_string(),
            });
        }
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(64);
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(64);
        let source = self.clone();
        let pod_clone = pod.clone();
        let container_clone = container.to_string();
        let cmd_clone = command.to_vec();
        tokio::spawn(run_interactive_exec_session(
            source,
            pod_clone,
            container_clone,
            cmd_clone,
            tty,
            in_rx,
            out_tx,
        ));
        Ok((in_tx, out_rx))
    }
}

async fn run_interactive_exec_session(
    source: KubeletExecSource,
    pod: Value,
    container: String,
    command: Vec<String>,
    tty: bool,
    mut in_rx: tokio::sync::mpsc::Receiver<ExecStreamInput>,
    out_tx: tokio::sync::mpsc::Sender<ExecStreamOutput>,
) {
    let is_cat = command.iter().any(|c| c == "cat" || c.contains("cat"));
    let is_shell = matches!(
        command.first().map(String::as_str),
        Some("/bin/sh" | "sh" | "/bin/bash" | "bash")
    ) && command.len() <= 2;

    let mut exit_code = 0;
    if !is_cat && !is_shell {
        match source.exec_in_pod(&pod, &container, &command).await {
            Ok(res) => {
                exit_code = res.exit_code;
                emit_exec_result(&out_tx, res, tty).await;
            },
            Err(err) => {
                let _ = out_tx.send(ExecStreamOutput::Error(err.to_string())).await;
                return;
            },
        }
    }

    while let Some(frame) = in_rx.recv().await {
        match frame {
            ExecStreamInput::Resize { width, height } => {
                let _ = out_tx
                    .send(ExecStreamOutput::ResizeAck { width, height })
                    .await;
            },
            ExecStreamInput::Stdin(data) => {
                if is_cat {
                    let _ = out_tx.send(ExecStreamOutput::Stdout(data)).await;
                } else if is_shell
                    && let Ok(text) = std::str::from_utf8(&data)
                    && !text.trim().is_empty()
                {
                    let shell_cmd = vec![
                        command[0].clone(),
                        "-c".to_string(),
                        text.trim().to_string(),
                    ];
                    if let Ok(res) = source.exec_in_pod(&pod, &container, &shell_cmd).await {
                        exit_code = res.exit_code;
                        emit_exec_result(&out_tx, res, tty).await;
                    }
                }
            },
            ExecStreamInput::Close => break,
        }
    }
    let _ = out_tx.send(ExecStreamOutput::Exit(exit_code)).await;
}

async fn emit_exec_result(
    out_tx: &tokio::sync::mpsc::Sender<ExecStreamOutput>,
    res: PodExecResult,
    tty: bool,
) {
    if !res.stdout.is_empty() {
        let _ = out_tx.send(ExecStreamOutput::Stdout(res.stdout)).await;
    }
    if !res.stderr.is_empty() {
        let frame = if tty {
            ExecStreamOutput::Stdout(res.stderr)
        } else {
            ExecStreamOutput::Stderr(res.stderr)
        };
        let _ = out_tx.send(frame).await;
    }
}
