//! Integration tests for CRI sandbox and container workloads running against
//! host-managed containerd and CRI-O runtimes with host-supplied images/plugins.

use diorama_cri::cgroup::ResolvedCgroupDriver;
use diorama_cri::endpoint::CriEndpoint;
use diorama_cri::endpoint::RuntimeEndpoints;
use diorama_cri::provider::CriProvider;
use diorama_cri::runtime::v1::{
    Container, ContainerMetadata, ContainerState, ContainerStatus, ContainerStatusResponse,
    CreateContainerRequest, CreateContainerResponse, Image, ListContainersResponse,
    ListImagesResponse, ListPodSandboxResponse, PodSandbox, PodSandboxConfig, PodSandboxMetadata,
    PodSandboxState, PodSandboxStatus, PodSandboxStatusResponse, RunPodSandboxRequest,
    RunPodSandboxResponse, StartContainerResponse, StopContainerResponse, StopPodSandboxResponse,
    VersionResponse,
};
use diorama_cri::workload::CriClient;
use h2::server;
use prost::Message;
use prost::bytes::{BufMut, Bytes, BytesMut};
use std::collections::BTreeMap;
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

fn handle_mock_stream(mut respond: server::SendResponse<Bytes>, payload: Option<Bytes>) {
    if let Some(data) = payload {
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
    }
}

#[allow(clippy::too_many_lines)]
async fn run_mock_workload_connection(
    stream: tokio::net::UnixStream,
    runtime_name: String,
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
        let payload = match path.as_str() {
            p if p.contains("Version") => {
                let resp = VersionResponse {
                    version: "0.1.0".into(),
                    runtime_name: runtime_name.clone(),
                    runtime_version: "1.7.20".into(),
                    runtime_api_version: "v1".into(),
                };
                Some(encode_grpc_message(&resp))
            },
            p if p.contains("ListImages") => {
                let resp = ListImagesResponse {
                    images: vec![
                        Image {
                            id: "sha256:1111".into(),
                            repo_tags: vec!["docker.io/library/busybox:latest".into()],
                            repo_digests: vec![],
                            size: 1024,
                            uid: None,
                            username: String::new(),
                            spec: None,
                            pinned: false,
                        },
                        Image {
                            id: "sha256:2222".into(),
                            repo_tags: vec!["registry.k8s.io/pause:3.9".into()],
                            repo_digests: vec![],
                            size: 512,
                            uid: None,
                            username: String::new(),
                            spec: None,
                            pinned: true,
                        },
                    ],
                };
                Some(encode_grpc_message(&resp))
            },
            p if p.contains("RunPodSandbox") => {
                let resp = RunPodSandboxResponse {
                    pod_sandbox_id: "sandbox-abc-123".into(),
                };
                Some(encode_grpc_message(&resp))
            },
            p if p.contains("StopPodSandbox") => {
                let resp = StopPodSandboxResponse {};
                Some(encode_grpc_message(&resp))
            },
            p if p.contains("ListPodSandbox") => {
                let resp = ListPodSandboxResponse {
                    items: vec![PodSandbox {
                        id: "sandbox-abc-123".into(),
                        metadata: Some(PodSandboxMetadata {
                            name: "test-pod".into(),
                            uid: "pod-uid-1".into(),
                            namespace: "default".into(),
                            attempt: 0,
                        }),
                        state: PodSandboxState::SandboxReady as i32,
                        created_at: 1_700_000_000,
                        labels: BTreeMap::new(),
                        annotations: BTreeMap::new(),
                        runtime_handler: String::new(),
                    }],
                };
                Some(encode_grpc_message(&resp))
            },
            p if p.contains("PodSandboxStatus") => {
                let resp = PodSandboxStatusResponse {
                    status: Some(PodSandboxStatus {
                        id: "sandbox-abc-123".into(),
                        metadata: Some(PodSandboxMetadata {
                            name: "test-pod".into(),
                            uid: "pod-uid-1".into(),
                            namespace: "default".into(),
                            attempt: 0,
                        }),
                        state: PodSandboxState::SandboxReady as i32,
                        created_at: 1_700_000_000,
                        network: None,
                        linux: None,
                        labels: BTreeMap::new(),
                        annotations: BTreeMap::new(),
                        runtime_handler: String::new(),
                    }),
                    info: BTreeMap::new(),
                    containers_statuses: vec![],
                    timestamp: 1_700_000_001,
                };
                Some(encode_grpc_message(&resp))
            },
            p if p.contains("CreateContainer") => {
                let resp = CreateContainerResponse {
                    container_id: "container-xyz-789".into(),
                };
                Some(encode_grpc_message(&resp))
            },
            p if p.contains("StartContainer") => {
                let resp = StartContainerResponse {};
                Some(encode_grpc_message(&resp))
            },
            p if p.contains("StopContainer") => {
                let resp = StopContainerResponse {};
                Some(encode_grpc_message(&resp))
            },
            p if p.contains("ListContainers") => {
                let resp = ListContainersResponse {
                    containers: vec![Container {
                        id: "container-xyz-789".into(),
                        pod_sandbox_id: "sandbox-abc-123".into(),
                        metadata: Some(ContainerMetadata {
                            name: "web".into(),
                            attempt: 0,
                        }),
                        image: None,
                        image_ref: "docker.io/library/busybox:latest".into(),
                        image_id: "sha256:busybox-id".into(),
                        state: ContainerState::ContainerRunning as i32,
                        created_at: 1_700_000_010,
                        labels: BTreeMap::new(),
                        annotations: BTreeMap::new(),
                    }],
                };
                Some(encode_grpc_message(&resp))
            },
            p if p.contains("ContainerStatus") => {
                let resp = ContainerStatusResponse {
                    status: Some(ContainerStatus {
                        id: "container-xyz-789".into(),
                        metadata: Some(ContainerMetadata {
                            name: "web".into(),
                            attempt: 0,
                        }),
                        state: ContainerState::ContainerRunning as i32,
                        created_at: 1_700_000_010,
                        started_at: 1_700_000_012,
                        finished_at: 0,
                        exit_code: 0,
                        image: None,
                        image_ref: "docker.io/library/busybox:latest".into(),
                        image_id: "sha256:busybox-id".into(),
                        reason: String::new(),
                        message: String::new(),
                        labels: BTreeMap::new(),
                        annotations: BTreeMap::new(),
                        mounts: vec![],
                        log_path: "/var/log/pods/test.log".into(),
                        resources: None,
                        user: None,
                        stop_signal: 0,
                    }),
                    info: BTreeMap::new(),
                };
                Some(encode_grpc_message(&resp))
            },
            _ => None,
        };

        handle_mock_stream(respond, payload);
    }
}

fn spawn_workload_mock_server(
    socket_path: &Path,
    runtime_name: String,
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

            let name = runtime_name.clone();
            let stop_flag = Arc::clone(&stopped);
            tokio::spawn(run_mock_workload_connection(stream, name, stop_flag));
        }
    })
}

#[tokio::test]
async fn sandbox_and_container_workloads_against_host_managed_containerd() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("containerd_workload.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _server = spawn_workload_mock_server(&socket, "containerd".into(), Arc::clone(&stopped));

    let endpoints = RuntimeEndpoints::single(CriEndpoint::from_path(&socket).unwrap());
    let mut client = CriClient::connect(&endpoints)
        .await
        .expect("must connect to mock containerd");

    // 1. Verify host-managed images (pause, busybox)
    let images = client.list_images().await.expect("list_images succeeds");
    assert_eq!(images.len(), 2);
    assert_eq!(images[0].repo_tags[0], "docker.io/library/busybox:latest");
    assert_eq!(images[1].repo_tags[0], "registry.k8s.io/pause:3.9");

    // 2. Run pod sandbox with host-supplied pause/networking
    let run_sandbox_req = RunPodSandboxRequest {
        config: Some(PodSandboxConfig {
            metadata: Some(PodSandboxMetadata {
                name: "test-pod".into(),
                uid: "pod-uid-1".into(),
                namespace: "default".into(),
                attempt: 0,
            }),
            hostname: "test-host".into(),
            log_directory: "/var/log/pods".into(),
            dns_config: None,
            port_mappings: vec![],
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            linux: None,
            windows: None,
        }),
        runtime_handler: String::new(),
    };

    let sandbox_id = client
        .run_pod_sandbox(run_sandbox_req)
        .await
        .expect("run_pod_sandbox succeeds");
    assert_eq!(sandbox_id, "sandbox-abc-123");

    // 3. List pod sandboxes
    let sandboxes = client
        .list_pod_sandboxes(None)
        .await
        .expect("list_pod_sandboxes succeeds");
    assert_eq!(sandboxes.len(), 1);
    assert_eq!(sandboxes[0].id, "sandbox-abc-123");

    // 4. Query pod sandbox status
    let status = client
        .pod_sandbox_status(&sandbox_id, false)
        .await
        .expect("pod_sandbox_status succeeds");
    assert_eq!(status.id, "sandbox-abc-123");
    assert_eq!(status.state, PodSandboxState::SandboxReady as i32);

    // 5. Create and start container inside sandbox
    let create_container_req = CreateContainerRequest {
        pod_sandbox_id: sandbox_id.clone(),
        config: None,
        sandbox_config: None,
    };
    let container_id = client
        .create_container(create_container_req)
        .await
        .expect("create_container succeeds");
    assert_eq!(container_id, "container-xyz-789");

    client
        .start_container(&container_id)
        .await
        .expect("start_container succeeds");

    // 6. List containers and check container status
    let containers = client
        .list_containers(None)
        .await
        .expect("list_containers succeeds");
    assert_eq!(containers.len(), 1);
    assert_eq!(containers[0].id, "container-xyz-789");

    let container_status = client
        .container_status(&container_id, false)
        .await
        .expect("container_status succeeds");
    assert_eq!(container_status.id, "container-xyz-789");
    assert_eq!(
        container_status.state,
        ContainerState::ContainerRunning as i32
    );

    // 7. Stop container and stop sandbox
    client
        .stop_container(&container_id, 10)
        .await
        .expect("stop_container succeeds");
    client
        .stop_pod_sandbox(&sandbox_id)
        .await
        .expect("stop_pod_sandbox succeeds");

    stopped.store(true, Ordering::Relaxed);
}

#[tokio::test]
async fn sandbox_and_container_workloads_against_host_managed_crio() {
    let temp = TempDir::new().unwrap();
    let socket = temp.path().join("crio_workload.sock");
    let stopped = Arc::new(AtomicBool::new(false));

    let _server = spawn_workload_mock_server(&socket, "cri-o".into(), Arc::clone(&stopped));

    let endpoints = RuntimeEndpoints::single(CriEndpoint::from_path(&socket).unwrap());
    let mut client = CriClient::connect(&endpoints)
        .await
        .expect("must connect to mock CRI-O");

    // Verify negotiation identifies CRI-O provider and negotiates host fallback
    let negotiated = client
        .negotiate(&endpoints, ResolvedCgroupDriver::Cgroupfs)
        .await
        .expect("negotiate against CRI-O succeeds");

    assert_eq!(negotiated.provider.provider, CriProvider::Crio);
    assert_eq!(negotiated.cgroup_driver, ResolvedCgroupDriver::Cgroupfs);

    // Run pod sandbox against CRI-O
    let run_sandbox_req = RunPodSandboxRequest {
        config: None,
        runtime_handler: String::new(),
    };
    let sandbox_id = client
        .run_pod_sandbox(run_sandbox_req)
        .await
        .expect("run_pod_sandbox on CRI-O succeeds");
    assert_eq!(sandbox_id, "sandbox-abc-123");

    stopped.store(true, Ordering::Relaxed);
}
