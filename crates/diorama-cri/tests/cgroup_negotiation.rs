//! Integration tests for CRI `RuntimeConfig` query, cgroup driver negotiation,
//! host fallback on absent/unimplemented configs, and consumer settings delivery.

use diorama_cri::cgroup::{
    CgroupDriverSource, ResolvedCgroupDriver, evaluate_host_cgroup_driver, negotiate_cgroup_driver,
    query_cgroup_driver,
};
use diorama_cri::client::connect_unix;
use diorama_cri::consumer::NegotiatedRuntime;
use diorama_cri::endpoint::{CriEndpoint, RuntimeEndpoints};
use diorama_cri::provider::ProviderInfo;
use diorama_cri::runtime::v1::{
    LinuxRuntimeConfiguration, ListImagesResponse, RuntimeConfigResponse, VersionResponse,
};
use h2::server;
use prost::Message;
use prost::bytes::{BufMut, Bytes, BytesMut};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::UnixListener;
use tonic::codegen::http::{HeaderMap, Response, StatusCode};

fn encode_grpc_message<M: Message>(msg: &M) -> Bytes {
    let mut encoded = Vec::new();
    msg.encode(&mut encoded).expect("encode protobuf message");
    let mut buf = BytesMut::with_capacity(5 + encoded.len());
    buf.put_u8(0);
    let len = u32::try_from(encoded.len()).expect("message length fits in u32");
    buf.put_u32(len);
    buf.put_slice(&encoded);
    buf.freeze()
}

#[derive(Clone, Debug)]
enum MockRuntimeConfigBehavior {
    /// Return explicit driver: 0 for systemd, 1 for cgroupfs, or other numbers.
    Explicit(i32),
    /// Return `RuntimeConfigResponse` with linux = None (absent Linux configuration).
    AbsentLinux,
    /// Return gRPC Unimplemented status code.
    Unimplemented,
}

fn build_runtime_config_response(
    behavior: &MockRuntimeConfigBehavior,
) -> Result<Option<Bytes>, (StatusCode, &'static str, &'static str)> {
    match behavior {
        MockRuntimeConfigBehavior::Explicit(driver) => {
            let resp = RuntimeConfigResponse {
                linux: Some(LinuxRuntimeConfiguration {
                    cgroup_driver: *driver,
                }),
            };
            Ok(Some(encode_grpc_message(&resp)))
        },
        MockRuntimeConfigBehavior::AbsentLinux => {
            let resp = RuntimeConfigResponse { linux: None };
            Ok(Some(encode_grpc_message(&resp)))
        },
        MockRuntimeConfigBehavior::Unimplemented => {
            // gRPC UNIMPLEMENTED status is code 12
            Err((StatusCode::OK, "12", "RuntimeConfig is not implemented"))
        },
    }
}

fn handle_mock_stream(
    mut respond: server::SendResponse<Bytes>,
    payload: Result<Option<Bytes>, (StatusCode, &'static str, &'static str)>,
) {
    match payload {
        Ok(Some(data)) => {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let Ok(mut send_stream) = respond.send_response(response, false) else {
                return;
            };
            let _ = send_stream.send_data(data, false);
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            let _ = send_stream.send_trailers(trailers);
        },
        Ok(None) => {},
        Err((_http_status, grpc_status, grpc_message)) => {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/grpc")
                .header("grpc-status", grpc_status)
                .header("grpc-message", grpc_message)
                .body(())
                .unwrap();
            let _ = respond.send_response(response, true);
        },
    }
}

async fn run_mock_connection(
    stream: tokio::net::UnixStream,
    behavior: MockRuntimeConfigBehavior,
    stop_flag: Arc<AtomicBool>,
) {
    let Ok(mut h2) = server::handshake(stream).await else {
        return;
    };

    while let Some(req_result) = h2.accept().await {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        let Ok((request, respond)) = req_result else {
            break;
        };

        let path = request.uri().path().to_string();
        let payload = if path.contains("Version") {
            let resp = VersionResponse {
                version: "0.1.0".into(),
                runtime_name: "containerd".into(),
                runtime_version: "1.7.20".into(),
                runtime_api_version: "v1".into(),
            };
            Ok(Some(encode_grpc_message(&resp)))
        } else if path.contains("ListImages") {
            let resp = ListImagesResponse { images: vec![] };
            Ok(Some(encode_grpc_message(&resp)))
        } else if path.contains("RuntimeConfig") {
            build_runtime_config_response(&behavior)
        } else {
            Ok(None)
        };

        handle_mock_stream(respond, payload);
    }
}

fn spawn_mock_server(
    socket_path: &Path,
    behavior: MockRuntimeConfigBehavior,
    stopped: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let listener = UnixListener::bind(socket_path).expect("bind mock unix socket");
    tokio::spawn(async move {
        while !stopped.load(Ordering::Relaxed) {
            let Ok(Ok((stream, _))) =
                tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
            else {
                continue;
            };

            let beh = behavior.clone();
            let stop_flag = Arc::clone(&stopped);
            tokio::spawn(run_mock_connection(stream, beh, stop_flag));
        }
    })
}

#[tokio::test]
async fn runtime_reports_systemd_driver_reaching_consumer_settings() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("cgroup_systemd.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _server = spawn_mock_server(
        &socket,
        MockRuntimeConfigBehavior::Explicit(0), // 0 = Systemd
        Arc::clone(&stopped),
    );

    let channel = connect_unix(&socket)
        .await
        .expect("must connect to mock CRI socket");
    let query_res = query_cgroup_driver(channel.clone())
        .await
        .expect("query must succeed");
    assert_eq!(query_res, Some(ResolvedCgroupDriver::Systemd));

    let (driver, source) = negotiate_cgroup_driver(channel, ResolvedCgroupDriver::Cgroupfs).await;
    assert_eq!(driver, ResolvedCgroupDriver::Systemd);
    assert_eq!(source, CgroupDriverSource::CriRuntimeConfig);

    // Verify consumer delivery
    let endpoints = RuntimeEndpoints::single(CriEndpoint::from_path(&socket).unwrap());
    let provider = ProviderInfo::new("containerd", "1.7.20", "v1");
    let negotiated = NegotiatedRuntime::new(provider, endpoints, driver, source);

    let kubelet = negotiated.kubelet_settings();
    assert_eq!(kubelet.cgroup_driver, ResolvedCgroupDriver::Systemd);
    assert_eq!(
        negotiated.kubelet_cli_args(),
        vec![
            format!("--container-runtime-endpoint=unix://{}", socket.display()),
            "--cgroup-driver=systemd".to_string(),
        ]
    );

    stopped.store(true, Ordering::Relaxed);
}

#[tokio::test]
async fn runtime_reports_cgroupfs_driver_reaching_consumer_settings() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("cgroup_cgroupfs.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _server = spawn_mock_server(
        &socket,
        MockRuntimeConfigBehavior::Explicit(1), // 1 = Cgroupfs
        Arc::clone(&stopped),
    );

    let channel = connect_unix(&socket)
        .await
        .expect("must connect to mock CRI socket");
    let query_res = query_cgroup_driver(channel.clone())
        .await
        .expect("query must succeed");
    assert_eq!(query_res, Some(ResolvedCgroupDriver::Cgroupfs));

    let (driver, source) = negotiate_cgroup_driver(channel, ResolvedCgroupDriver::Systemd).await;
    assert_eq!(driver, ResolvedCgroupDriver::Cgroupfs);
    assert_eq!(source, CgroupDriverSource::CriRuntimeConfig);

    // Verify consumer delivery
    let endpoints = RuntimeEndpoints::single(CriEndpoint::from_path(&socket).unwrap());
    let provider = ProviderInfo::new("containerd", "1.7.20", "v1");
    let negotiated = NegotiatedRuntime::new(provider, endpoints, driver, source);

    let kubelet = negotiated.kubelet_settings();
    assert_eq!(kubelet.cgroup_driver, ResolvedCgroupDriver::Cgroupfs);
    assert_eq!(
        negotiated.kubelet_cli_args(),
        vec![
            format!("--container-runtime-endpoint=unix://{}", socket.display()),
            "--cgroup-driver=cgroupfs".to_string(),
        ]
    );

    stopped.store(true, Ordering::Relaxed);
}

#[tokio::test]
async fn absent_linux_config_falls_back_to_host_detection_not_protobuf_zero_systemd() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("cgroup_absent.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _server = spawn_mock_server(
        &socket,
        MockRuntimeConfigBehavior::AbsentLinux,
        Arc::clone(&stopped),
    );

    let channel = connect_unix(&socket)
        .await
        .expect("must connect to mock CRI socket");

    // Must be None on absent Linux configuration, NOT Some(Systemd)
    let query_res = query_cgroup_driver(channel.clone())
        .await
        .expect("query must succeed");
    assert_eq!(
        query_res, None,
        "Absent Linux configuration must return None and NOT fabricate protobuf-zero Systemd"
    );

    // Fall back to host-detected driver (e.g. Alpine non-systemd host)
    let host_fallback = evaluate_host_cgroup_driver(true, false); // cgroup v2, but no systemd
    assert_eq!(host_fallback, ResolvedCgroupDriver::Cgroupfs);

    let (driver, source) = negotiate_cgroup_driver(channel, host_fallback).await;
    assert_eq!(
        driver,
        ResolvedCgroupDriver::Cgroupfs,
        "Absent Linux configuration must fall back to host-detected cgroupfs"
    );
    assert_eq!(source, CgroupDriverSource::HostFallback);

    stopped.store(true, Ordering::Relaxed);
}

#[tokio::test]
async fn unimplemented_rpc_falls_back_to_host_detection() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("cgroup_unimplemented.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _server = spawn_mock_server(
        &socket,
        MockRuntimeConfigBehavior::Unimplemented,
        Arc::clone(&stopped),
    );

    let channel = connect_unix(&socket)
        .await
        .expect("must connect to mock CRI socket");

    // Unimplemented RPC returns Ok(None) to allow seamless host fallback
    let query_res = query_cgroup_driver(channel.clone())
        .await
        .expect("unimplemented RPC must yield Ok(None)");
    assert_eq!(query_res, None);

    let (driver, source) = negotiate_cgroup_driver(channel, ResolvedCgroupDriver::Cgroupfs).await;
    assert_eq!(driver, ResolvedCgroupDriver::Cgroupfs);
    assert_eq!(source, CgroupDriverSource::HostFallback);

    stopped.store(true, Ordering::Relaxed);
}

#[tokio::test]
async fn unknown_driver_enum_number_falls_back_to_host_detection() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("cgroup_unknown_enum.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _server = spawn_mock_server(
        &socket,
        MockRuntimeConfigBehavior::Explicit(17), // unknown enum value 17
        Arc::clone(&stopped),
    );

    let channel = connect_unix(&socket)
        .await
        .expect("must connect to mock CRI socket");

    let query_res = query_cgroup_driver(channel.clone())
        .await
        .expect("query must succeed");
    assert_eq!(
        query_res, None,
        "Unknown cgroup driver enum number must return None"
    );

    let (driver, source) = negotiate_cgroup_driver(channel, ResolvedCgroupDriver::Systemd).await;
    assert_eq!(driver, ResolvedCgroupDriver::Systemd);
    assert_eq!(source, CgroupDriverSource::HostFallback);

    stopped.store(true, Ordering::Relaxed);
}
