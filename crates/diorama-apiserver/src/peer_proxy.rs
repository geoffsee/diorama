//! Cross-node `PodLogReader` and `PodExec` proxy over `tokio-quiche` (`ClientH3Driver`).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::SinkExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio_quiche::ClientH3Driver;
use tokio_quiche::ConnectionParams;
use tokio_quiche::http3::driver::{
    ClientH3Event, H3Event, InboundFrame, IncomingH3Headers, NewClientRequest, OutboundFrame,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quiche::h3::Header;
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::socket::Socket;

use crate::error::ApiserverError;
use crate::exec::{ExecStreamInput, ExecStreamOutput, PodExec, PodExecResult};
use crate::logs::{PodLogOptions, PodLogReader};
use crate::storage::KubernetesStorage;

pub const DEFAULT_KUBELET_QUIC_PORT: u16 = 10255;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteLogRequest {
    pub pod: Value,
    pub container: Option<String>,
    pub tail_lines: Option<usize>,
    pub timestamps: bool,
    pub since_seconds: Option<u64>,
    pub previous: bool,
    pub follow: bool,
    pub limit_bytes: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteLogResponse {
    Ok(String),
    BadRequest(String),
    Internal(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteLogStreamChunk {
    Chunk(String),
    BadRequest(String),
    Internal(String),
    Eof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteExecRequest {
    pub pod: Value,
    pub container: String,
    pub command: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteExecStreamHeader {
    pub pod: Value,
    pub container: String,
    pub command: Vec<String>,
    pub tty: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteExecResponse {
    Ok {
        exit_code: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    BadRequest(String),
    Internal(String),
}

#[derive(Clone, Debug)]
pub struct ClusterPodRouter {
    local_node_name: String,
    storage: KubernetesStorage,
    local_log_reader: Option<Arc<dyn PodLogReader>>,
    local_exec: Option<Arc<dyn PodExec>>,
    peer_endpoints: Arc<RwLock<BTreeMap<String, SocketAddr>>>,
    default_kubelet_quic_port: u16,
    client_cert_file: Option<PathBuf>,
    client_key_file: Option<PathBuf>,
}

impl ClusterPodRouter {
    #[must_use]
    pub fn new(local_node_name: impl Into<String>, storage: KubernetesStorage) -> Self {
        Self {
            local_node_name: local_node_name.into(),
            storage,
            local_log_reader: None,
            local_exec: None,
            peer_endpoints: Arc::new(RwLock::new(BTreeMap::new())),
            default_kubelet_quic_port: DEFAULT_KUBELET_QUIC_PORT,
            client_cert_file: None,
            client_key_file: None,
        }
    }

    #[must_use]
    pub fn with_local_log_reader(mut self, reader: Arc<dyn PodLogReader>) -> Self {
        self.local_log_reader = Some(reader);
        self
    }

    #[must_use]
    pub fn with_local_exec(mut self, exec: Arc<dyn PodExec>) -> Self {
        self.local_exec = Some(exec);
        self
    }

    #[must_use]
    pub fn with_client_tls(
        mut self,
        cert_file: impl Into<PathBuf>,
        key_file: impl Into<PathBuf>,
    ) -> Self {
        self.client_cert_file = Some(cert_file.into());
        self.client_key_file = Some(key_file.into());
        self
    }

    pub fn register_peer_endpoint(&self, node_name: impl Into<String>, addr: SocketAddr) {
        self.peer_endpoints
            .write()
            .unwrap()
            .insert(node_name.into(), addr);
    }

    fn is_local_node(&self, node_name: &str) -> bool {
        if node_name.is_empty() || node_name == self.local_node_name {
            return true;
        }
        let companion = format!("{}-2", self.local_node_name);
        node_name == companion
    }

    async fn resolve_peer_addr(&self, node_name: &str) -> Result<SocketAddr, ApiserverError> {
        if let Some(addr) = self.peer_endpoints.read().unwrap().get(node_name).copied() {
            return Ok(addr);
        }
        let key = format!("/registry/minions/{node_name}");
        let kv = self
            .storage
            .client()
            .get(&key)
            .await
            .map_err(|e| ApiserverError::Internal {
                reason: format!("failed to query node {node_name}: {e}"),
            })?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "nodes".into(),
                name: node_name.to_string(),
            })?;
        let node_doc: Value =
            serde_json::from_slice(&kv.value).map_err(|e| ApiserverError::Internal {
                reason: format!("corrupt node document for {node_name}: {e}"),
            })?;
        if let Some(addr_str) = node_doc
            .pointer("/metadata/annotations/diorama.io~1kubelet-quic-endpoint")
            .and_then(Value::as_str)
            && let Ok(sock) = addr_str.parse::<SocketAddr>()
        {
            return Ok(sock);
        }
        let ip_str = node_doc
            .pointer("/status/addresses")
            .and_then(Value::as_array)
            .and_then(|addrs| {
                addrs
                    .iter()
                    .find(|a| a.get("type").and_then(Value::as_str) == Some("InternalIP"))
                    .and_then(|a| a.get("address").and_then(Value::as_str))
            })
            .ok_or_else(|| ApiserverError::Internal {
                reason: format!("node {node_name} has no InternalIP address"),
            })?;
        let ip: IpAddr = ip_str.parse().map_err(|e| ApiserverError::Internal {
            reason: format!("invalid InternalIP {ip_str} on node {node_name}: {e}"),
        })?;
        Ok(SocketAddr::new(ip, self.default_kubelet_quic_port))
    }

    async fn open_h3_stream(
        &self,
        peer_addr: SocketAddr,
        path: &[u8],
    ) -> Result<
        (
            tokio_quiche::http3::driver::OutboundFrameSender,
            tokio_quiche::ClientH3Controller,
            Box<dyn Send + Sync>,
        ),
        ApiserverError,
    > {
        let bind_addr: SocketAddr = if peer_addr.is_ipv4() {
            "127.0.0.1:0".parse().unwrap()
        } else {
            "[::1]:0".parse().unwrap()
        };
        let udp = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| ApiserverError::Internal {
                reason: format!("failed to bind UDP socket for kubelet proxy: {e}"),
            })?;
        udp.connect(peer_addr)
            .await
            .map_err(|e| ApiserverError::Internal {
                reason: format!("failed to connect UDP socket to {peer_addr}: {e}"),
            })?;
        let socket = Socket::try_from(udp).map_err(|e| ApiserverError::Internal {
            reason: format!("socket conversion error: {e}"),
        })?;

        let cert_str = self
            .client_cert_file
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned());
        let key_str = self
            .client_key_file
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned());
        let tls_cert = match (&cert_str, &key_str) {
            (Some(c), Some(k)) => Some(TlsCertificatePaths {
                cert: c,
                private_key: k,
                kind: CertificateKind::X509,
            }),
            _ => None,
        };

        let mut settings = QuicSettings::default();
        settings.max_idle_timeout = Some(Duration::from_secs(15));
        settings.max_recv_udp_payload_size = 1400;
        settings.max_send_udp_payload_size = 1400;
        settings.disable_client_ip_validation = true;
        settings.verify_peer = false;

        let params = ConnectionParams::new_client(settings, tls_cert, Hooks::default());
        let (driver, controller) = ClientH3Driver::new(Http3Settings::default());
        let quic_conn =
            tokio_quiche::quic::connect_with_config(socket, Some("localhost"), &params, driver)
                .await
                .map_err(|e| ApiserverError::Internal {
                    reason: format!("tokio-quiche connect to kubelet {peer_addr} failed: {e}"),
                })?;

        let (body_tx, body_rx) = oneshot::channel();
        controller
            .request_sender()
            .send(NewClientRequest {
                request_id: 1,
                headers: vec![
                    Header::new(b":method", b"POST"),
                    Header::new(b":scheme", b"https"),
                    Header::new(b":authority", b"localhost"),
                    Header::new(b":path", path),
                ],
                body_writer: Some(body_tx),
            })
            .map_err(|_| ApiserverError::Internal {
                reason: "failed to send H3 request to kubelet driver".into(),
            })?;

        let send = body_rx.await.map_err(|_| ApiserverError::Internal {
            reason: "failed to obtain OutboundFrameSender for kubelet request".into(),
        })?;
        Ok((send, controller, Box::new(quic_conn)))
    }

    async fn send_h3_rpc(
        &self,
        peer_addr: SocketAddr,
        path: &[u8],
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, ApiserverError> {
        let (mut send, mut controller, _quic_conn) =
            Box::pin(self.open_h3_stream(peer_addr, path)).await?;
        send.send(OutboundFrame::Body(Bytes::from(payload), true))
            .await
            .map_err(|_| ApiserverError::Internal {
                reason: "failed to write request body to kubelet stream".into(),
            })?;

        let mut response_body = BytesMut::new();
        while let Some(event) = controller.event_receiver_mut().recv().await {
            if let ClientH3Event::Core(H3Event::IncomingHeaders(IncomingH3Headers {
                mut recv,
                read_fin,
                ..
            })) = event
            {
                if !read_fin {
                    collect_inbound_body(&mut recv, &mut response_body).await;
                }
                break;
            }
        }

        Ok(response_body.to_vec())
    }
}

async fn collect_inbound_body(
    recv: &mut tokio_quiche::http3::driver::InboundFrameStream,
    response_body: &mut BytesMut,
) {
    while let Some(InboundFrame::Body(chunk, fin)) = recv.recv().await {
        response_body.extend_from_slice(&chunk);
        if fin {
            break;
        }
    }
}

async fn pump_log_stream_chunks(
    mut controller: tokio_quiche::ClientH3Controller,
    keep_conn: Box<dyn Send + Sync>,
    tx: tokio::sync::mpsc::Sender<Result<String, ApiserverError>>,
) {
    let _keep = keep_conn;
    while let Some(event) = controller.event_receiver_mut().recv().await {
        if let ClientH3Event::Core(H3Event::IncomingHeaders(IncomingH3Headers {
            mut recv, ..
        })) = event
        {
            read_log_stream_lines(&mut recv, &tx).await;
            break;
        }
    }
}

async fn read_log_stream_lines(
    recv: &mut tokio_quiche::http3::driver::InboundFrameStream,
    tx: &tokio::sync::mpsc::Sender<Result<String, ApiserverError>>,
) {
    let mut line_buf = Vec::new();
    while let Some(InboundFrame::Body(chunk, fin)) = recv.recv().await {
        line_buf.extend_from_slice(&chunk);
        while let Some(pos) = line_buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = line_buf.drain(..=pos).collect();
            let Ok(item) = serde_json::from_slice::<RemoteLogStreamChunk>(&line) else {
                continue;
            };
            let res = match item {
                RemoteLogStreamChunk::Chunk(s) => Ok(s),
                RemoteLogStreamChunk::BadRequest(message) => {
                    Err(ApiserverError::BadRequest { message })
                },
                RemoteLogStreamChunk::Internal(reason) => Err(ApiserverError::Internal { reason }),
                RemoteLogStreamChunk::Eof => return,
            };
            if tx.send(res).await.is_err() {
                return;
            }
        }
        if fin {
            break;
        }
    }
}

async fn pump_exec_stream(
    mut send: tokio_quiche::http3::driver::OutboundFrameSender,
    mut controller: tokio_quiche::ClientH3Controller,
    keep_conn: Box<dyn Send + Sync>,
    mut in_rx: tokio::sync::mpsc::Receiver<ExecStreamInput>,
    out_tx: tokio::sync::mpsc::Sender<ExecStreamOutput>,
) {
    let _keep = keep_conn;
    let send_task = tokio::spawn(async move {
        while let Some(input) = in_rx.recv().await {
            let is_close = matches!(input, ExecStreamInput::Close);
            let Ok(mut line) = serde_json::to_vec(&input) else {
                continue;
            };
            line.push(b'\n');
            if send
                .send(OutboundFrame::Body(Bytes::from(line), is_close))
                .await
                .is_err()
                || is_close
            {
                break;
            }
        }
    });

    while let Some(event) = controller.event_receiver_mut().recv().await {
        if let ClientH3Event::Core(H3Event::IncomingHeaders(IncomingH3Headers {
            mut recv, ..
        })) = event
        {
            read_exec_stream_lines(&mut recv, &out_tx).await;
            break;
        }
    }
    send_task.abort();
}

async fn read_exec_stream_lines(
    recv: &mut tokio_quiche::http3::driver::InboundFrameStream,
    out_tx: &tokio::sync::mpsc::Sender<ExecStreamOutput>,
) {
    let mut line_buf = Vec::new();
    while let Some(InboundFrame::Body(chunk, fin)) = recv.recv().await {
        line_buf.extend_from_slice(&chunk);
        while let Some(pos) = line_buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = line_buf.drain(..=pos).collect();
            let Ok(item) = serde_json::from_slice::<ExecStreamOutput>(&line) else {
                continue;
            };
            let is_exit = matches!(item, ExecStreamOutput::Exit(_));
            if out_tx.send(item).await.is_err() || is_exit {
                return;
            }
        }
        if fin {
            break;
        }
    }
}

#[async_trait]
impl PodLogReader for ClusterPodRouter {
    async fn read_pod_log(
        &self,
        pod: &Value,
        options: &PodLogOptions,
    ) -> Result<String, ApiserverError> {
        let assigned_node = pod
            .pointer("/spec/nodeName")
            .and_then(Value::as_str)
            .unwrap_or("");
        if self.is_local_node(assigned_node) {
            let reader =
                self.local_log_reader
                    .as_ref()
                    .ok_or_else(|| ApiserverError::Internal {
                        reason: "local PodLogReader is not registered".into(),
                    })?;
            return reader.read_pod_log(pod, options).await;
        }

        let peer_addr = self.resolve_peer_addr(assigned_node).await?;
        let req = RemoteLogRequest {
            pod: pod.clone(),
            container: options.container.clone(),
            tail_lines: options.tail_lines,
            timestamps: options.timestamps,
            since_seconds: options.since_seconds,
            previous: options.previous,
            follow: options.follow,
            limit_bytes: options.limit_bytes,
        };
        let req_bytes = serde_json::to_vec(&req).map_err(|e| ApiserverError::Internal {
            reason: format!("failed to serialize RemoteLogRequest: {e}"),
        })?;
        let resp_bytes = self.send_h3_rpc(peer_addr, b"/pods/log", req_bytes).await?;
        let resp: RemoteLogResponse =
            serde_json::from_slice(&resp_bytes).map_err(|e| ApiserverError::Internal {
                reason: format!("invalid RemoteLogResponse from {assigned_node}: {e}"),
            })?;
        match resp {
            RemoteLogResponse::Ok(logs) => Ok(logs),
            RemoteLogResponse::BadRequest(message) => Err(ApiserverError::BadRequest { message }),
            RemoteLogResponse::Internal(reason) => Err(ApiserverError::Internal { reason }),
        }
    }

    async fn stream_pod_log(
        &self,
        pod: &Value,
        options: &PodLogOptions,
    ) -> Result<tokio::sync::mpsc::Receiver<Result<String, ApiserverError>>, ApiserverError> {
        let assigned_node = pod
            .pointer("/spec/nodeName")
            .and_then(Value::as_str)
            .unwrap_or("");
        if self.is_local_node(assigned_node) {
            let reader =
                self.local_log_reader
                    .as_ref()
                    .ok_or_else(|| ApiserverError::Internal {
                        reason: "local PodLogReader is not registered".into(),
                    })?;
            return reader.stream_pod_log(pod, options).await;
        }

        let peer_addr = self.resolve_peer_addr(assigned_node).await?;
        let req = RemoteLogRequest {
            pod: pod.clone(),
            container: options.container.clone(),
            tail_lines: options.tail_lines,
            timestamps: options.timestamps,
            since_seconds: options.since_seconds,
            previous: options.previous,
            follow: true,
            limit_bytes: options.limit_bytes,
        };
        let req_bytes = serde_json::to_vec(&req).map_err(|e| ApiserverError::Internal {
            reason: format!("failed to serialize RemoteLogRequest: {e}"),
        })?;
        let (mut send, controller, quic_conn) =
            Box::pin(self.open_h3_stream(peer_addr, b"/pods/log/stream")).await?;
        send.send(OutboundFrame::Body(Bytes::from(req_bytes), true))
            .await
            .map_err(|_| ApiserverError::Internal {
                reason: "failed to write log stream request to kubelet".into(),
            })?;

        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(pump_log_stream_chunks(controller, quic_conn, tx));
        Ok(rx)
    }
}

#[async_trait]
impl PodExec for ClusterPodRouter {
    async fn exec_in_pod(
        &self,
        pod: &Value,
        container: &str,
        command: &[String],
    ) -> Result<PodExecResult, ApiserverError> {
        let assigned_node = pod
            .pointer("/spec/nodeName")
            .and_then(Value::as_str)
            .unwrap_or("");
        if self.is_local_node(assigned_node) {
            let exec = self
                .local_exec
                .as_ref()
                .ok_or_else(|| ApiserverError::Internal {
                    reason: "local PodExec is not registered".into(),
                })?;
            return exec.exec_in_pod(pod, container, command).await;
        }

        let peer_addr = self.resolve_peer_addr(assigned_node).await?;
        let req = RemoteExecRequest {
            pod: pod.clone(),
            container: container.to_string(),
            command: command.to_vec(),
        };
        let req_bytes = serde_json::to_vec(&req).map_err(|e| ApiserverError::Internal {
            reason: format!("failed to serialize RemoteExecRequest: {e}"),
        })?;
        let resp_bytes = self
            .send_h3_rpc(peer_addr, b"/pods/exec", req_bytes)
            .await?;
        let resp: RemoteExecResponse =
            serde_json::from_slice(&resp_bytes).map_err(|e| ApiserverError::Internal {
                reason: format!("invalid RemoteExecResponse from {assigned_node}: {e}"),
            })?;
        match resp {
            RemoteExecResponse::Ok {
                exit_code,
                stdout,
                stderr,
            } => Ok(PodExecResult {
                exit_code,
                stdout,
                stderr,
            }),
            RemoteExecResponse::BadRequest(message) => Err(ApiserverError::BadRequest { message }),
            RemoteExecResponse::Internal(reason) => Err(ApiserverError::Internal { reason }),
        }
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
        let assigned_node = pod
            .pointer("/spec/nodeName")
            .and_then(Value::as_str)
            .unwrap_or("");
        if self.is_local_node(assigned_node) {
            let exec = self
                .local_exec
                .as_ref()
                .ok_or_else(|| ApiserverError::Internal {
                    reason: "local PodExec is not registered".into(),
                })?;
            return exec.stream_exec_in_pod(pod, container, command, tty).await;
        }

        let peer_addr = self.resolve_peer_addr(assigned_node).await?;
        let header = RemoteExecStreamHeader {
            pod: pod.clone(),
            container: container.to_string(),
            command: command.to_vec(),
            tty,
        };
        let mut header_bytes =
            serde_json::to_vec(&header).map_err(|e| ApiserverError::Internal {
                reason: format!("failed to serialize RemoteExecStreamHeader: {e}"),
            })?;
        header_bytes.push(b'\n');

        let (mut send, controller, quic_conn) =
            Box::pin(self.open_h3_stream(peer_addr, b"/pods/exec/stream")).await?;
        send.send(OutboundFrame::Body(Bytes::from(header_bytes), false))
            .await
            .map_err(|_| ApiserverError::Internal {
                reason: "failed to write exec stream header to kubelet".into(),
            })?;

        let (in_tx, in_rx) = tokio::sync::mpsc::channel(64);
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(pump_exec_stream(send, controller, quic_conn, in_rx, out_tx));
        Ok((in_tx, out_rx))
    }
}
