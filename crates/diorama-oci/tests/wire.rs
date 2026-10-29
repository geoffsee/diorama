//! Interoperability with oci-cri's actual gRPC service and generated protocol.
//! The fake engine exercises the service without Linux privileges or images.

use dioramalet::{CriRuntimeProvider, RuntimeProvider};
use std::sync::Arc;
use std::time::Duration;

use diorama_cri::runtime::v1::{
    ContainerConfig, ContainerMetadata, ContainerState, CreateContainerRequest, PodSandboxConfig,
    PodSandboxMetadata, RunPodSandboxRequest,
};
use diorama_cri::{
    CriClient, CriProvider, ResolvedCgroupDriver, RuntimeEndpoints, image_spec, probe_cri_readiness,
};

fn sandbox_config(dir: &std::path::Path) -> PodSandboxConfig {
    PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: "wire-test".into(),
            uid: "wire-test-uid".into(),
            namespace: "default".into(),
            attempt: 0,
        }),
        log_directory: dir.join("logs").to_string_lossy().into_owned(),
        ..Default::default()
    }
}

#[tokio::test]
async fn oci_cri_wire_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("cri.sock");
    let root = dir.path().join("root");
    let config = oci_cri::Config {
        socket: socket.clone(),
        root: root.clone(),
        state_root: dir.path().join("state"),
        sandbox_image: "fake/pause:latest".into(),
        ..Default::default()
    };
    let engine = Arc::new(oci_cri::test_support::FakeEngine::new(root));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(oci_cri::server::serve_with_engine_until(
        config,
        engine,
        async {
            let _ = stopped.await;
        },
    ));
    let endpoints = RuntimeEndpoints::parse(socket.to_str().unwrap(), None).unwrap();
    let info = probe_cri_readiness(
        &endpoints,
        Duration::from_secs(5),
        Duration::from_millis(10),
    )
    .await
    .unwrap();
    assert_eq!(info.provider, CriProvider::OciCri);
    assert_eq!(info.runtime_api_version, "v1");

    let provider = CriRuntimeProvider::new(&socket);
    provider.check_available().await.unwrap();
    assert_eq!(provider.provider_name(), "oci-cri");
    assert_eq!(provider.runtime_version(), info.runtime_version);

    let mut client = CriClient::connect(&endpoints).await.unwrap();
    let negotiated = client
        .negotiate(&endpoints, ResolvedCgroupDriver::Systemd)
        .await
        .unwrap();
    assert_eq!(negotiated.provider.provider, CriProvider::OciCri);
    assert_eq!(negotiated.cgroup_driver, ResolvedCgroupDriver::Cgroupfs);
    client.pull_image("fake/app:latest").await.unwrap();
    assert!(
        client
            .image_status("fake/app:latest", false)
            .await
            .unwrap()
            .is_some()
    );

    let sandbox_config = sandbox_config(dir.path());
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(sandbox_config.clone()),
            runtime_handler: String::new(),
        })
        .await
        .unwrap();
    let container = client
        .create_container(CreateContainerRequest {
            pod_sandbox_id: sandbox.clone(),
            config: Some(ContainerConfig {
                metadata: Some(ContainerMetadata {
                    name: "app".into(),
                    attempt: 0,
                }),
                image: Some(image_spec("fake/app:latest")),
                command: vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
                log_path: "app/0.log".into(),
                ..Default::default()
            }),
            sandbox_config: Some(sandbox_config),
        })
        .await
        .unwrap();
    client.start_container(&container).await.unwrap();
    let status = client.container_status(&container, false).await.unwrap();
    assert_eq!(status.state, ContainerState::ContainerRunning as i32);
    let exec = client
        .exec_sync(&container, vec!["/bin/echo".into(), "oci-cri".into()], 5)
        .await
        .unwrap();
    assert_eq!(exec.exit_code, 0);
    assert_eq!(exec.stdout, b"oci-cri\n");
    client.stop_container(&container, 0).await.unwrap();
    client.remove_container(&container).await.unwrap();
    client.stop_pod_sandbox(&sandbox).await.unwrap();
    client.remove_pod_sandbox(&sandbox).await.unwrap();
    assert_eq!(client.list_containers(None).await.unwrap(), []);
    assert_eq!(client.list_pod_sandboxes(None).await.unwrap(), []);
    drop(client);
    drop(provider);
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!socket.exists());
}
