//! Integration tests for external CRI provider selection, endpoint validation,
//! readiness probing, and non-destructive supervisor attachment.

use diorama_cri::endpoint::{CriEndpoint, EndpointError, RuntimeEndpoints};
use diorama_cri::external::{
    COMPONENT_EXTERNAL_CRI, ExternalRuntimeOptions, ExternalRuntimeService,
};
use diorama_cri::provider::{CriProvider, detect_provider};
use diorama_cri::readiness::{ReadinessError, probe_cri_readiness};
use diorama_cri::runtime::v1::{ListImagesResponse, VersionResponse};
use diorama_supervisor::{
    ComponentKind, FailurePolicy, Registration, StopCause, Supervisor, stop_channel,
};
use h2::server;
use prost::Message;
use prost::bytes::{BufMut, Bytes, BytesMut};
use std::path::{Path, PathBuf};
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
    buf.put_u8(0); // no compression flag
    let len = u32::try_from(encoded.len()).expect("message length fits in u32");
    buf.put_u32(len);
    buf.put_slice(&encoded);
    buf.freeze()
}

fn build_mock_payload(path: &str, runtime_name: &str, runtime_version: &str) -> Option<Bytes> {
    if path.contains("Version") {
        let resp = VersionResponse {
            version: "0.1.0".into(),
            runtime_name: runtime_name.to_string(),
            runtime_version: runtime_version.to_string(),
            runtime_api_version: "v1".into(),
        };
        Some(encode_grpc_message(&resp))
    } else if path.contains("ListImages") {
        let resp = ListImagesResponse { images: vec![] };
        Some(encode_grpc_message(&resp))
    } else {
        None
    }
}

fn handle_mock_h2_stream(mut respond: server::SendResponse<Bytes>, payload: Bytes) {
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .body(())
        .unwrap();
    let Ok(mut send_stream) = respond.send_response(response, false) else {
        return;
    };
    let _ = send_stream.send_data(payload, false);
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().unwrap());
    let _ = send_stream.send_trailers(trailers);
}

async fn run_mock_connection(
    stream: tokio::net::UnixStream,
    runtime_name: String,
    runtime_version: String,
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
        if let Some(data) = build_mock_payload(&path, &runtime_name, &runtime_version) {
            handle_mock_h2_stream(respond, data);
        }
    }
}

/// Spawns a mock CRI server on a Unix domain socket serving `Version` and `ListImages` RPCs.
fn spawn_mock_cri_server(
    socket_path: PathBuf,
    runtime_name: String,
    runtime_version: String,
    stopped: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = UnixListener::bind(&socket_path).expect("bind mock unix socket");
        while !stopped.load(Ordering::Relaxed) {
            let Ok(Ok((stream, _))) =
                tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
            else {
                continue;
            };

            let name = runtime_name.clone();
            let ver = runtime_version.clone();
            let stop_flag = Arc::clone(&stopped);

            tokio::spawn(run_mock_connection(stream, name, ver, stop_flag));
        }
    })
}

#[tokio::test]
async fn containerd_readiness_probe_succeeds() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("containerd.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _server = spawn_mock_cri_server(
        socket.clone(),
        "containerd".into(),
        "1.7.20".into(),
        Arc::clone(&stopped),
    );

    let endpoints = RuntimeEndpoints::single(CriEndpoint::from_path(&socket).unwrap());
    let info = probe_cri_readiness(
        &endpoints,
        Duration::from_secs(3),
        Duration::from_millis(50),
    )
    .await
    .expect("containerd probe must succeed");

    assert_eq!(info.provider, CriProvider::Containerd);
    assert_eq!(info.runtime_name, "containerd");
    assert_eq!(info.runtime_version, "1.7.20");
    assert!(info.provider.is_supported());

    stopped.store(true, Ordering::Relaxed);
}

#[tokio::test]
async fn crio_readiness_probe_succeeds() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("crio.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _server = spawn_mock_cri_server(
        socket.clone(),
        "cri-o".into(),
        "1.30.0".into(),
        Arc::clone(&stopped),
    );

    let endpoints = RuntimeEndpoints::single(CriEndpoint::from_path(&socket).unwrap());
    let info = probe_cri_readiness(
        &endpoints,
        Duration::from_secs(3),
        Duration::from_millis(50),
    )
    .await
    .expect("cri-o probe must succeed");

    assert_eq!(info.provider, CriProvider::Crio);
    assert_eq!(info.runtime_name, "cri-o");
    assert_eq!(info.runtime_version, "1.30.0");
    assert!(info.provider.is_supported());

    stopped.store(true, Ordering::Relaxed);
}

#[tokio::test]
async fn unsupported_provider_fails_readiness() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("docker.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _server = spawn_mock_cri_server(
        socket.clone(),
        "dockershim".into(),
        "v1.23.0".into(),
        Arc::clone(&stopped),
    );

    let endpoints = RuntimeEndpoints::single(CriEndpoint::from_path(&socket).unwrap());
    let err = probe_cri_readiness(
        &endpoints,
        Duration::from_secs(3),
        Duration::from_millis(50),
    )
    .await
    .expect_err("dockershim probe must fail as unsupported");

    match err {
        ReadinessError::UnsupportedProvider {
            runtime_name,
            runtime_version,
        } => {
            assert_eq!(runtime_name, "dockershim");
            assert_eq!(runtime_version, "v1.23.0");
        },
        other => panic!("expected UnsupportedProvider error, got: {other:?}"),
    }

    stopped.store(true, Ordering::Relaxed);
}

#[tokio::test]
async fn separate_runtime_and_image_sockets() {
    let temp = TempDir::new().unwrap();
    let runtime_sock = temp.path().join("runtime.sock");
    let image_sock = temp.path().join("image.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _runtime_srv = spawn_mock_cri_server(
        runtime_sock.clone(),
        "containerd".into(),
        "2.0.0".into(),
        Arc::clone(&stopped),
    );

    let _image_srv = spawn_mock_cri_server(
        image_sock.clone(),
        "containerd".into(),
        "2.0.0".into(),
        Arc::clone(&stopped),
    );

    let endpoints = RuntimeEndpoints::new(
        CriEndpoint::from_path(&runtime_sock).unwrap(),
        Some(CriEndpoint::from_path(&image_sock).unwrap()),
    );

    let info = probe_cri_readiness(
        &endpoints,
        Duration::from_secs(3),
        Duration::from_millis(50),
    )
    .await
    .expect("dual endpoint probe must succeed");

    assert_eq!(info.provider, CriProvider::Containerd);
    assert_eq!(info.runtime_version, "2.0.0");

    stopped.store(true, Ordering::Relaxed);
}

#[tokio::test]
async fn missing_socket_times_out() {
    let temp = TempDir::new().unwrap();
    let non_existent = temp.path().join("missing.sock");
    let endpoints = RuntimeEndpoints::single(CriEndpoint::from_path(&non_existent).unwrap());

    let err = probe_cri_readiness(
        &endpoints,
        Duration::from_millis(150),
        Duration::from_millis(25),
    )
    .await
    .expect_err("probe on missing socket must time out");

    match err {
        ReadinessError::TimedOut { endpoint, elapsed } => {
            assert_eq!(endpoint, non_existent);
            assert_eq!(elapsed, Duration::from_millis(150));
        },
        other => panic!("expected TimedOut, got: {other:?}"),
    }
}

#[test]
fn endpoint_parsing_and_defaults() {
    use std::str::FromStr;

    // Valid raw unix path
    let ep1 = CriEndpoint::from_str("/run/containerd/containerd.sock").unwrap();
    assert_eq!(ep1.path(), Path::new("/run/containerd/containerd.sock"));
    assert_eq!(ep1.uri(), "unix:///run/containerd/containerd.sock");

    // Valid unix:// URI
    let ep2 = CriEndpoint::from_str("unix:///var/run/crio/crio.sock").unwrap();
    assert_eq!(ep2.path(), Path::new("/var/run/crio/crio.sock"));

    // Rejection of invalid schemes
    assert_eq!(
        CriEndpoint::from_str("tcp://127.0.0.1:2376").unwrap_err(),
        EndpointError::UnsupportedScheme {
            scheme: "tcp".into(),
            input: "tcp://127.0.0.1:2376".into(),
        }
    );
    assert_eq!(
        CriEndpoint::from_str("http://localhost:8080").unwrap_err(),
        EndpointError::UnsupportedScheme {
            scheme: "http".into(),
            input: "http://localhost:8080".into(),
        }
    );

    // Empty path
    assert_eq!(
        CriEndpoint::from_str("   ").unwrap_err(),
        EndpointError::Empty
    );

    // RuntimeEndpoints defaulting
    let ep = CriEndpoint::from_str("/run/containerd/containerd.sock").unwrap();
    let dual = RuntimeEndpoints::single(ep.clone());
    assert_eq!(dual.runtime, ep);
    assert_eq!(dual.image, ep);
}

#[test]
fn provider_detection_logic() {
    assert_eq!(detect_provider("containerd"), CriProvider::Containerd);
    assert_eq!(detect_provider("CONTAINERD"), CriProvider::Containerd);
    assert_eq!(
        detect_provider("io.containerd.runc.v2"),
        CriProvider::Containerd
    );
    assert_eq!(detect_provider("cri-o"), CriProvider::Crio);
    assert_eq!(detect_provider("CRI-O"), CriProvider::Crio);
    assert_eq!(detect_provider("crio"), CriProvider::Crio);
    assert_eq!(
        detect_provider("docker"),
        CriProvider::Unsupported("docker".into())
    );
    assert_eq!(
        detect_provider("dockershim"),
        CriProvider::Unsupported("dockershim".into())
    );
    assert_eq!(
        detect_provider("frakti"),
        CriProvider::Unsupported("frakti".into())
    );
}

#[test]
fn external_cri_component_spec() {
    let timeout = Duration::from_secs(45);
    let spec = ExternalRuntimeService::component_spec(timeout);

    assert_eq!(spec.id, COMPONENT_EXTERNAL_CRI);
    assert_eq!(spec.kind, ComponentKind::LongRunning);
    assert_eq!(spec.failure_policy, FailurePolicy::Fatal);
    assert_eq!(spec.startup_timeout, timeout);
    assert!(spec.prerequisites.is_empty());
}

#[tokio::test]
async fn external_runtime_service_supervision_lifecycle() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("supervised_cri.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _server = spawn_mock_cri_server(
        socket.clone(),
        "containerd".into(),
        "1.7.19".into(),
        Arc::clone(&stopped),
    );

    let endpoints = RuntimeEndpoints::single(CriEndpoint::from_path(&socket).unwrap());
    let mut options = ExternalRuntimeOptions::new(endpoints);
    options.readiness_timeout = Duration::from_secs(3);
    options.retry_interval = Duration::from_millis(50);

    let service = ExternalRuntimeService::new(options);
    let spec = ExternalRuntimeService::component_spec(Duration::from_secs(5));
    let registration = Registration::new(spec, service);

    let (stop_handle, stop_receiver) = stop_channel();
    let supervisor = Supervisor::new(vec![registration]).expect("valid component graph");

    // Spawn supervisor in background
    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    // Give time for readiness probe to pass and service to become ready
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Trigger graceful supervisor stop
    stop_handle.stop();

    let report = sup_handle.await.expect("supervisor task should join");
    assert!(
        matches!(report.cause, StopCause::Requested),
        "Supervisor cause should be Requested on graceful stop, got {:?}",
        report.cause
    );
    assert!(
        report.failures.is_empty(),
        "No failures expected on graceful stop"
    );

    stopped.store(true, Ordering::Relaxed);
}

#[tokio::test]
async fn external_mode_does_not_mutate_socket_or_manage_host_process() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("external_readonly.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _server = spawn_mock_cri_server(
        socket.clone(),
        "cri-o".into(),
        "1.29.1".into(),
        Arc::clone(&stopped),
    );

    let endpoints = RuntimeEndpoints::single(CriEndpoint::from_path(&socket).unwrap());
    let mut options = ExternalRuntimeOptions::new(endpoints);
    options.readiness_timeout = Duration::from_secs(2);
    options.retry_interval = Duration::from_millis(50);

    let service = ExternalRuntimeService::new(options);
    let info = service.probe().await.expect("readiness probe succeeds");
    assert_eq!(info.provider, CriProvider::Crio);

    // Socket still exists and was not deleted or altered
    assert!(socket.exists());

    // No files or directories were created inside the temp dir other than the socket
    let entries: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], "external_readonly.sock");

    stopped.store(true, Ordering::Relaxed);
}
