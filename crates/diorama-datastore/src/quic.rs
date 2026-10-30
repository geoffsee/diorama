//! Full-duplex HTTP/3 over QUIC transport for `diorama-datastore` powered by `tokio-quiche`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use diorama_pki::cluster::ClusterPki;
use diorama_pki::token::{JoinRequest, JoinResponse, JoinRole};
use futures_util::{SinkExt, StreamExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio_quiche::http3::driver::{
    ClientH3Event, H3Event, InboundFrame, InboundFrameStream, IncomingH3Headers, NewClientRequest,
    OutboundFrame, OutboundFrameSender, ServerH3Event,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quiche::h3::{Header, NameValue};
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::socket::Socket;
use tokio_quiche::{ClientH3Driver, ConnectionParams, ServerH3Driver, listen};

use crate::engine::DatastoreEngine;
use crate::error::DatastoreError;
use crate::model::{RemoteKvRequest, RemoteKvResponse, WatchReceiver};
use crate::raft::{FrameDecoder, ProposalOutcome, RaftMessage, encode_frame};

const RAFT_STREAM_PATH: &[u8] = b"/diorama.datastore.v1/raft";
const JOIN_PATH: &[u8] = b"/diorama.datastore.v1/join";
const KV_RPC_PATH: &[u8] = b"/diorama.datastore.v1/kv";
const NODE_ID_HEADER: &[u8] = b"x-diorama-node-id";
const MAX_JOIN_BODY_BYTES: usize = 512 * 1024;
const MAX_KV_RPC_BYTES: usize = 16 * 1024 * 1024;

fn default_quic_settings() -> QuicSettings {
    let mut settings = QuicSettings::default();
    settings.max_idle_timeout = Some(Duration::from_secs(30));
    settings.max_recv_udp_payload_size = 1400;
    settings.max_send_udp_payload_size = 1400;
    settings.disable_client_ip_validation = true;
    settings.verify_peer = false;
    settings
}

pub async fn start_quic_server(
    listen_addr: SocketAddr,
    cert_file: PathBuf,
    key_file: PathBuf,
    engine: DatastoreEngine,
) -> Result<SocketAddr, DatastoreError> {
    let udp = match UdpSocket::bind(listen_addr).await {
        Ok(sock) => sock,
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
            let fallback = SocketAddr::new(listen_addr.ip(), 0);
            UdpSocket::bind(fallback).await?
        },
        Err(err) => return Err(DatastoreError::Io(err)),
    };
    let local_addr = udp.local_addr()?;

    let cert_str = cert_file.to_string_lossy().into_owned();
    let key_str = key_file.to_string_lossy().into_owned();
    let tls_cert = TlsCertificatePaths {
        cert: &cert_str,
        private_key: &key_str,
        kind: CertificateKind::X509,
    };
    let params = ConnectionParams::new_server(default_quic_settings(), tls_cert, Hooks::default());
    let mut listeners = listen([udp], params, DefaultMetrics)?;
    let mut accept_stream = listeners.remove(0);

    tokio::spawn(async move {
        while let Some(Ok(conn)) = accept_stream.next().await {
            let (driver, controller) = ServerH3Driver::new(Http3Settings::default());
            let quic_conn = conn.start(driver);
            tokio::spawn(handle_server_connection(
                engine.clone(),
                local_addr,
                controller,
                quic_conn,
            ));
        }
    });

    Ok(local_addr)
}

async fn handle_server_connection<T: Send + 'static>(
    engine: DatastoreEngine,
    local_addr: SocketAddr,
    mut controller: tokio_quiche::ServerH3Controller,
    quic_conn: T,
) {
    let _keep_alive = quic_conn;
    while let Some(event) = controller.event_receiver_mut().recv().await {
        if let ServerH3Event::Headers {
            incoming_headers, ..
        } = event
        {
            tokio::spawn(handle_server_stream(
                engine.clone(),
                local_addr,
                incoming_headers,
            ));
        }
    }
}

async fn handle_server_stream(
    engine: DatastoreEngine,
    local_addr: SocketAddr,
    incoming: IncomingH3Headers,
) {
    let IncomingH3Headers {
        headers,
        mut send,
        recv,
        ..
    } = incoming;

    let path = headers
        .iter()
        .find(|h| h.name() == b":path")
        .map(NameValue::value);
    if path == Some(JOIN_PATH) {
        handle_join_stream(engine, local_addr, send, recv).await;
        return;
    }
    if path == Some(KV_RPC_PATH) {
        handle_kv_rpc_stream(engine, send, recv).await;
        return;
    }

    let peer_id = headers
        .iter()
        .find(|h| h.name().eq_ignore_ascii_case(NODE_ID_HEADER))
        .and_then(|h| std::str::from_utf8(h.value()).ok())
        .and_then(|v| v.parse::<u64>().ok());

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

    run_full_duplex_stream(engine, peer_id, send, recv).await;
}

async fn handle_join_stream(
    engine: DatastoreEngine,
    local_addr: SocketAddr,
    mut send: OutboundFrameSender,
    mut recv: InboundFrameStream,
) {
    let mut body = Vec::new();
    while let Some(frame) = recv.recv().await {
        if let InboundFrame::Body(chunk, fin) = frame {
            if body.len().saturating_add(chunk.len()) > MAX_JOIN_BODY_BYTES {
                return;
            }
            body.extend_from_slice(&chunk);
            if fin {
                break;
            }
        }
    }

    let response = match serde_json::from_slice::<JoinRequest>(&body) {
        Ok(req) => evaluate_join_request(&engine, local_addr, req).await,
        Err(err) => JoinResponse::Rejected(format!("invalid join request payload: {err}")),
    };

    let Ok(resp_bytes) = serde_json::to_vec(&response) else {
        return;
    };
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
    let _ = send
        .send(OutboundFrame::Body(Bytes::from(resp_bytes), true))
        .await;
}

async fn handle_kv_rpc_stream(
    engine: DatastoreEngine,
    mut send: OutboundFrameSender,
    mut recv: InboundFrameStream,
) {
    let mut body = Vec::new();
    while let Some(frame) = recv.recv().await {
        if let InboundFrame::Body(chunk, fin) = frame {
            if body.len().saturating_add(chunk.len()) > MAX_KV_RPC_BYTES {
                return;
            }
            body.extend_from_slice(&chunk);
            if fin {
                break;
            }
        }
    }

    let Ok(req) = serde_json::from_slice::<RemoteKvRequest>(&body) else {
        return;
    };

    if let RemoteKvRequest::Watch { prefix } = req {
        stream_watch_events(engine, prefix, send).await;
        return;
    }

    let resp = execute_kv_rpc(&engine, req).await;
    let Ok(resp_bytes) = serde_json::to_vec(&resp) else {
        return;
    };
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
    let _ = send
        .send(OutboundFrame::Body(Bytes::from(resp_bytes), true))
        .await;
}

async fn execute_kv_rpc(engine: &DatastoreEngine, req: RemoteKvRequest) -> RemoteKvResponse {
    match req {
        RemoteKvRequest::CurrentRevision => {
            RemoteKvResponse::Revision(engine.current_revision().await)
        },
        RemoteKvRequest::Get { key } => {
            RemoteKvResponse::Value(engine.get(&key).await.ok().flatten())
        },
        RemoteKvRequest::List { prefix } => {
            RemoteKvResponse::List(engine.list(&prefix).await.unwrap_or_default())
        },
        RemoteKvRequest::Create { key, value } => RemoteKvResponse::Mutated(
            ProposalOutcome::from_create_result(engine.create(&key, value).await),
        ),
        RemoteKvRequest::Update {
            key,
            value,
            expected_mod_revision,
        } => RemoteKvResponse::Mutated(ProposalOutcome::from_update_result(
            engine.update(&key, value, expected_mod_revision).await,
        )),
        RemoteKvRequest::Delete {
            key,
            expected_mod_revision,
        } => RemoteKvResponse::Mutated(ProposalOutcome::from_delete_result(
            engine.delete(&key, expected_mod_revision).await,
        )),
        RemoteKvRequest::Watch { .. } => RemoteKvResponse::Revision(0),
    }
}

async fn stream_watch_events(
    engine: DatastoreEngine,
    prefix: String,
    mut send: OutboundFrameSender,
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
    let mut watch_rx = engine.watch(&prefix).await;
    while let Ok(event) = watch_rx.recv().await {
        let Ok(mut payload) = serde_json::to_vec(&event) else {
            continue;
        };
        payload.push(b'\n');
        if send
            .send(OutboundFrame::Body(Bytes::from(payload), false))
            .await
            .is_err()
        {
            break;
        }
    }
}

pub async fn execute_remote_kv_rpc(
    peer_addr: SocketAddr,
    cert_file: Option<&std::path::Path>,
    key_file: Option<&std::path::Path>,
    request: &RemoteKvRequest,
) -> Result<RemoteKvResponse, DatastoreError> {
    let bind_addr: SocketAddr = if peer_addr.is_ipv4() {
        "127.0.0.1:0".parse().unwrap()
    } else {
        "[::1]:0".parse().unwrap()
    };
    let udp = UdpSocket::bind(bind_addr).await?;
    udp.connect(peer_addr).await?;
    let socket = Socket::try_from(udp)?;

    let cert_str = cert_file.map(|p| p.to_string_lossy().into_owned());
    let key_str = key_file.map(|p| p.to_string_lossy().into_owned());
    let tls_cert = match (&cert_str, &key_str) {
        (Some(c), Some(k)) => Some(TlsCertificatePaths {
            cert: c,
            private_key: k,
            kind: CertificateKind::X509,
        }),
        _ => None,
    };

    let params = ConnectionParams::new_client(default_quic_settings(), tls_cert, Hooks::default());
    let (driver, mut controller) = ClientH3Driver::new(Http3Settings::default());
    let quic_conn =
        tokio_quiche::quic::connect_with_config(socket, Some("localhost"), &params, driver)
            .await
            .map_err(|err| DatastoreError::Fatal(format!("tokio-quiche kv connect: {err}")))?;

    let (body_tx, body_rx) = oneshot::channel();
    let req = NewClientRequest {
        request_id: 1,
        headers: vec![
            Header::new(b":method", b"POST"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"localhost"),
            Header::new(b":path", KV_RPC_PATH),
        ],
        body_writer: Some(body_tx),
    };
    controller
        .request_sender()
        .send(req)
        .map_err(|_| DatastoreError::Fatal("failed to dispatch H3 kv request".into()))?;

    let mut send = body_rx
        .await
        .map_err(|_| DatastoreError::Fatal("failed to obtain H3 kv body sender".into()))?;
    let payload = serde_json::to_vec(request)?;
    send.send(OutboundFrame::Body(Bytes::from(payload), true))
        .await
        .map_err(|_| DatastoreError::Fatal("failed to send H3 kv payload".into()))?;

    let _keep_conn = quic_conn;
    let resp_bytes = read_client_response_body(&mut controller).await;
    let response: RemoteKvResponse = serde_json::from_slice(&resp_bytes)
        .map_err(|err| DatastoreError::Fatal(format!("invalid H3 kv response: {err}")))?;
    Ok(response)
}

pub async fn start_remote_kv_watch(
    peer_addr: SocketAddr,
    cert_file: Option<PathBuf>,
    key_file: Option<PathBuf>,
    prefix: String,
) -> WatchReceiver {
    let (tx, rx) = mpsc::channel(256);
    tokio::spawn(async move {
        let _ = run_remote_kv_watch_stream(peer_addr, cert_file, key_file, prefix, tx).await;
    });
    WatchReceiver::new(rx)
}

async fn run_remote_kv_watch_stream(
    peer_addr: SocketAddr,
    cert_file: Option<PathBuf>,
    key_file: Option<PathBuf>,
    prefix: String,
    tx: mpsc::Sender<crate::model::WatchEvent>,
) -> Result<(), DatastoreError> {
    let bind_addr: SocketAddr = if peer_addr.is_ipv4() {
        "127.0.0.1:0".parse().unwrap()
    } else {
        "[::1]:0".parse().unwrap()
    };
    let udp = UdpSocket::bind(bind_addr).await?;
    udp.connect(peer_addr).await?;
    let socket = Socket::try_from(udp)?;

    let cert_str = cert_file.as_ref().map(|p| p.to_string_lossy().into_owned());
    let key_str = key_file.as_ref().map(|p| p.to_string_lossy().into_owned());
    let tls_cert = match (&cert_str, &key_str) {
        (Some(c), Some(k)) => Some(TlsCertificatePaths {
            cert: c,
            private_key: k,
            kind: CertificateKind::X509,
        }),
        _ => None,
    };

    let params = ConnectionParams::new_client(default_quic_settings(), tls_cert, Hooks::default());
    let (driver, mut controller) = ClientH3Driver::new(Http3Settings::default());
    let quic_conn =
        tokio_quiche::quic::connect_with_config(socket, Some("localhost"), &params, driver)
            .await
            .map_err(|err| DatastoreError::Fatal(format!("tokio-quiche watch connect: {err}")))?;

    let (body_tx, body_rx) = oneshot::channel();
    let req = NewClientRequest {
        request_id: 1,
        headers: vec![
            Header::new(b":method", b"POST"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"localhost"),
            Header::new(b":path", KV_RPC_PATH),
        ],
        body_writer: Some(body_tx),
    };
    controller
        .request_sender()
        .send(req)
        .map_err(|_| DatastoreError::Fatal("failed to dispatch H3 watch request".into()))?;

    let mut send = body_rx
        .await
        .map_err(|_| DatastoreError::Fatal("failed to obtain H3 watch body sender".into()))?;
    let payload = serde_json::to_vec(&RemoteKvRequest::Watch { prefix })?;
    send.send(OutboundFrame::Body(Bytes::from(payload), true))
        .await
        .map_err(|_| DatastoreError::Fatal("failed to send H3 watch payload".into()))?;

    let _keep_conn = quic_conn;
    read_watch_stream_events(&mut controller, &tx).await;
    Ok(())
}

async fn read_watch_stream_events(
    controller: &mut tokio_quiche::ClientH3Controller,
    tx: &mpsc::Sender<crate::model::WatchEvent>,
) {
    while let Some(event) = controller.event_receiver_mut().recv().await {
        if let ClientH3Event::Core(H3Event::IncomingHeaders(IncomingH3Headers {
            mut recv, ..
        })) = event
        {
            pump_watch_body_frames(&mut recv, tx).await;
            break;
        }
    }
}

async fn pump_watch_body_frames(
    recv: &mut tokio_quiche::http3::driver::InboundFrameStream,
    tx: &mpsc::Sender<crate::model::WatchEvent>,
) {
    let mut line_buf = Vec::new();
    while let Some(InboundFrame::Body(chunk, fin)) = recv.recv().await {
        line_buf.extend_from_slice(&chunk);
        while let Some(pos) = line_buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = line_buf.drain(..=pos).collect();
            if let Ok(evt) = serde_json::from_slice::<crate::model::WatchEvent>(&line)
                && tx.send(evt).await.is_err()
            {
                return;
            }
        }
        if fin {
            break;
        }
    }
}

async fn evaluate_join_request(
    engine: &DatastoreEngine,
    local_addr: SocketAddr,
    req: JoinRequest,
) -> JoinResponse {
    let Some(ca_file) = &engine.config().ca_file else {
        return JoinResponse::Rejected("seed node PKI directory is not configured".into());
    };
    let Some(pki_dir) = ca_file.parent() else {
        return JoinResponse::Rejected("invalid seed node PKI directory".into());
    };
    let Ok(ca_cert_pem) = std::fs::read_to_string(pki_dir.join("ca.crt")) else {
        return JoinResponse::Rejected("failed to read seed cluster ca.crt".into());
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Err(err) = req.token.verify(Some(&ca_cert_pem), now_secs) {
        return JoinResponse::Rejected(format!("join token verification failed: {err}"));
    }
    if let Err(reason) = engine.verify_bootstrap_token(&req.token, now_secs).await {
        return JoinResponse::Rejected(reason);
    }

    match req.token.role {
        JoinRole::Controller => {
            let joiner_peer_addr = req
                .listen_peer_addr
                .unwrap_or_else(|| SocketAddr::new(req.node_ip, 2380));
            let (assigned_id, peers) = engine
                .raft()
                .allocate_peer_id(local_addr, &engine.config().peers, joiner_peer_addr)
                .await;
            match ClusterPki::export_controller_join_material(pki_dir, assigned_id, peers) {
                Ok(material) => JoinResponse::Controller(Box::new(material)),
                Err(err) => {
                    JoinResponse::Rejected(format!("failed to export controller PKI: {err}"))
                },
            }
        },
        JoinRole::Worker => {
            match ClusterPki::issue_worker_join_material(
                pki_dir,
                &req.node_name,
                req.node_ip,
                &req.token.api_endpoint,
            ) {
                Ok(mut material) => {
                    material.assigned_node_id = engine.raft().allocate_worker_id();
                    material.peer_addr = Some(local_addr);
                    JoinResponse::Worker(Box::new(material))
                },
                Err(err) => JoinResponse::Rejected(format!("failed to issue worker PKI: {err}")),
            }
        },
    }
}

/// Sends a k0s-style node join request to the seed controller over `tokio-quiche` HTTP/3.
pub async fn request_cluster_join(
    peer_addr: SocketAddr,
    request: &JoinRequest,
) -> Result<JoinResponse, DatastoreError> {
    let bind_addr: SocketAddr = if peer_addr.is_ipv4() {
        "127.0.0.1:0".parse().unwrap()
    } else {
        "[::1]:0".parse().unwrap()
    };
    let udp = UdpSocket::bind(bind_addr).await?;
    udp.connect(peer_addr).await?;
    let socket = Socket::try_from(udp)?;

    let params = ConnectionParams::new_client(default_quic_settings(), None, Hooks::default());
    let (driver, mut controller) = ClientH3Driver::new(Http3Settings::default());
    let quic_conn =
        tokio_quiche::quic::connect_with_config(socket, Some("localhost"), &params, driver)
            .await
            .map_err(|err| DatastoreError::Fatal(format!("tokio-quiche join connect: {err}")))?;

    let (body_tx, body_rx) = oneshot::channel();
    let req = NewClientRequest {
        request_id: 1,
        headers: vec![
            Header::new(b":method", b"POST"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"localhost"),
            Header::new(b":path", JOIN_PATH),
        ],
        body_writer: Some(body_tx),
    };
    controller
        .request_sender()
        .send(req)
        .map_err(|_| DatastoreError::Fatal("failed to dispatch H3 join request".into()))?;

    let mut send = body_rx
        .await
        .map_err(|_| DatastoreError::Fatal("failed to obtain H3 join body sender".into()))?;
    let payload = serde_json::to_vec(request)?;
    send.send(OutboundFrame::Body(Bytes::from(payload), true))
        .await
        .map_err(|_| DatastoreError::Fatal("failed to send H3 join payload".into()))?;

    let _keep_conn = quic_conn;
    let resp_bytes = read_client_response_body(&mut controller).await;

    let response: JoinResponse = serde_json::from_slice(&resp_bytes)
        .map_err(|err| DatastoreError::Fatal(format!("invalid H3 join response: {err}")))?;
    Ok(response)
}

async fn read_client_response_body(controller: &mut tokio_quiche::ClientH3Controller) -> Vec<u8> {
    let mut resp_bytes = Vec::new();
    while let Some(event) = controller.event_receiver_mut().recv().await {
        if let ClientH3Event::Core(H3Event::IncomingHeaders(IncomingH3Headers {
            mut recv, ..
        })) = event
        {
            while let Some(InboundFrame::Body(chunk, fin)) = recv.recv().await {
                resp_bytes.extend_from_slice(&chunk);
                if fin {
                    break;
                }
            }
            break;
        }
    }
    resp_bytes
}

pub async fn connect_quic_peer(
    peer_id: u64,
    peer_addr: SocketAddr,
    cert_file: Option<PathBuf>,
    key_file: Option<PathBuf>,
    engine: DatastoreEngine,
) -> Result<(), DatastoreError> {
    let bind_addr: SocketAddr = if peer_addr.is_ipv4() {
        "127.0.0.1:0".parse().unwrap()
    } else {
        "[::1]:0".parse().unwrap()
    };
    let udp = UdpSocket::bind(bind_addr).await?;
    udp.connect(peer_addr).await?;
    let socket = Socket::try_from(udp)?;

    let cert_str = cert_file.as_ref().map(|p| p.to_string_lossy().into_owned());
    let key_str = key_file.as_ref().map(|p| p.to_string_lossy().into_owned());
    let tls_cert = match (&cert_str, &key_str) {
        (Some(c), Some(k)) => Some(TlsCertificatePaths {
            cert: c,
            private_key: k,
            kind: CertificateKind::X509,
        }),
        _ => None,
    };

    let params = ConnectionParams::new_client(default_quic_settings(), tls_cert, Hooks::default());
    let (driver, mut controller) = ClientH3Driver::new(Http3Settings::default());
    let quic_conn =
        tokio_quiche::quic::connect_with_config(socket, Some("localhost"), &params, driver)
            .await
            .map_err(|err| DatastoreError::Fatal(format!("tokio-quiche connect failed: {err}")))?;

    let (body_tx, body_rx) = oneshot::channel();
    let node_id_bytes = engine.raft().node_id().to_string().into_bytes();
    let req = NewClientRequest {
        request_id: 1,
        headers: vec![
            Header::new(b":method", b"POST"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"localhost"),
            Header::new(b":path", RAFT_STREAM_PATH),
            Header::new(NODE_ID_HEADER, &node_id_bytes),
        ],
        body_writer: Some(body_tx),
    };
    controller
        .request_sender()
        .send(req)
        .map_err(|_| DatastoreError::Fatal("failed to dispatch H3 request".into()))?;

    let send = body_rx
        .await
        .map_err(|_| DatastoreError::Fatal("failed to obtain OutboundFrameSender".into()))?;

    // Send an initial heartbeat/handshake frame to flush the request headers and open the stream
    let mut send_init = send;
    let init_frame = encode_frame(&RaftMessage::AppendEntriesAck {
        term: engine.raft().current_term().await,
        from_id: engine.raft().node_id(),
        match_revision: engine.current_revision().await,
        success: true,
    })?;
    send_init
        .send(OutboundFrame::Body(init_frame, false))
        .await
        .map_err(|_| DatastoreError::Fatal("failed to send initial stream frame".into()))?;

    tokio::spawn(async move {
        let _keep_conn = quic_conn;
        while let Some(event) = controller.event_receiver_mut().recv().await {
            if let ClientH3Event::Core(H3Event::IncomingHeaders(IncomingH3Headers {
                recv, ..
            })) = event
            {
                run_full_duplex_stream(engine, Some(peer_id), send_init, recv).await;
                break;
            }
        }
    });

    Ok(())
}

async fn current_peer_ids(engine: &DatastoreEngine) -> Vec<u64> {
    let mut peer_ids: Vec<u64> = engine.config().peers.keys().copied().collect();
    for id in engine.raft().dynamic_peers().await.keys().copied() {
        if !peer_ids.contains(&id) {
            peer_ids.push(id);
        }
    }
    peer_ids
}

async fn run_full_duplex_stream(
    engine: DatastoreEngine,
    peer_id: Option<u64>,
    mut send: OutboundFrameSender,
    mut recv: InboundFrameStream,
) {
    let (tx, mut rx) = mpsc::unbounded_channel::<RaftMessage>();
    if let Some(pid) = peer_id {
        engine.raft().register_peer_sender(pid, tx.clone()).await;
        if engine.raft().is_leader().await {
            let _ = engine.replicate_snapshot_to_peer(pid).await;
            engine.raft().broadcast_heartbeat().await;
        }
    }

    let mut decoder = FrameDecoder::new();

    loop {
        tokio::select! {
            Some(outbound_msg) = rx.recv() => {
                let Ok(bytes) = encode_frame(&outbound_msg) else {
                    continue;
                };
                if send.send(OutboundFrame::Body(bytes, false)).await.is_err() {
                    break;
                }
            }
            frame_opt = recv.recv() => {
                let Some(frame) = frame_opt else {
                    break;
                };
                if let InboundFrame::Body(chunk, fin) = frame {
                    if let Ok(messages) = decoder.push_and_decode(&chunk) {
                        let peer_ids = current_peer_ids(&engine).await;
                        for msg in messages {
                            if let Some((target_peer, reply)) = engine
                                .raft()
                                .handle_message(&engine, &peer_ids, msg)
                                .await
                                && (peer_id == Some(target_peer) || peer_id.is_none())
                            {
                                let _ = tx.send(reply);
                            }
                        }
                    }
                    if fin {
                        break;
                    }
                }
            }
        }
    }

    if let Some(pid) = peer_id {
        engine.raft().remove_peer_sender(pid).await;
    }
}
