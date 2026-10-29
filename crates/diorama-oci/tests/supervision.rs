use std::sync::Arc;
use std::time::Duration;

use diorama_cri::{RuntimeEndpoints, probe_cri_readiness};
use diorama_oci::{Config, OciCriService};
use diorama_supervisor::{Registration, StopCause, Supervisor, stop_channel};

#[tokio::test]
async fn supervised_server_stops_and_releases_both_listeners() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("cri.sock");
    let root = dir.path().join("root");
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = port.local_addr().unwrap();
    drop(port);
    let config = Config {
        socket: socket.clone(),
        root: root.clone(),
        state_root: dir.path().join("state"),
        streaming_port: address.port(),
        ..Default::default()
    };
    let engine = Arc::new(oci_cri::test_support::FakeEngine::new(root));
    let timeout = Duration::from_secs(5);
    let service = OciCriService::new(config, timeout).with_engine(engine);
    let supervisor = Supervisor::new(vec![Registration::new(
        OciCriService::component_spec(timeout),
        service,
    )])
    .unwrap();
    let (stop, stopped) = stop_channel();
    let task = tokio::spawn(supervisor.run(stopped));
    let endpoints = RuntimeEndpoints::parse(socket.to_str().unwrap(), None).unwrap();
    probe_cri_readiness(&endpoints, timeout, Duration::from_millis(10))
        .await
        .unwrap();
    // An idle streaming connection must not keep shutdown alive.
    let _stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stop.stop();
    let report = tokio::time::timeout(timeout, task).await.unwrap().unwrap();
    assert_eq!(report.cause, StopCause::Requested);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.cleanup_failures, []);
    assert!(!socket.exists());
    let _rebound = std::net::TcpListener::bind(address).unwrap();
}

#[tokio::test]
async fn occupied_streaming_port_fails_before_cri_becomes_ready() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("cri.sock");
    let root = dir.path().join("root");
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let config = Config {
        socket: socket.clone(),
        root: root.clone(),
        state_root: dir.path().join("state"),
        streaming_port: port.local_addr().unwrap().port(),
        ..Default::default()
    };
    let timeout = Duration::from_secs(5);
    let engine = Arc::new(oci_cri::test_support::FakeEngine::new(root));
    let service = OciCriService::new(config, timeout).with_engine(engine);
    let supervisor = Supervisor::new(vec![Registration::new(
        OciCriService::component_spec(timeout),
        service,
    )])
    .unwrap();
    let (_stop, stopped) = stop_channel();
    let report = tokio::time::timeout(timeout, supervisor.run(stopped))
        .await
        .unwrap();
    assert_ne!(report.failures, []);
    assert!(!socket.exists());
}
