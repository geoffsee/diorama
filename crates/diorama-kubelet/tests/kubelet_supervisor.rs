use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

use diorama_apiserver::supervisor::ApiserverAdapter;
use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_supervisor::{StopCause, Supervisor, stop_channel};
use dioramalet::{
    COMPONENT_KUBELET, KubeletAdapter, KubeletConfigOptions, KubeletService, MockRuntimeProvider,
};

fn setup_test_environment(dir: &TempDir) -> (ApiserverService, KubeletConfigOptions) {
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let datastore_dir = dir.path().join("datastore");
    let kubelet_dir = dir.path().join("kubelet");
    std::fs::create_dir_all(&kubelet_dir).unwrap();

    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "test-node".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir)).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    let apiserver_service = ApiserverService::new(apiserver_config, storage);

    let kubelet_options =
        KubeletConfigOptions::default_for_pki(&pki_dir, "test-node", "192.0.2.1", &kubelet_dir);

    (apiserver_service, kubelet_options)
}

#[tokio::test]
async fn test_kubelet_supervised_lifecycle() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options) = setup_test_environment(&temp);

    let apiserver_arc = Arc::new(apiserver.clone());
    let runtime = Arc::new(MockRuntimeProvider::new("containerd"));
    let kubelet_service = KubeletService::new(kubelet_options, apiserver_arc, runtime);

    let timeout = Duration::from_secs(10);
    let apiserver_reg = ApiserverAdapter::registration("apiserver", apiserver, Vec::new(), timeout);
    let kubelet_reg = KubeletAdapter::registration(
        COMPONENT_KUBELET,
        kubelet_service.clone(),
        vec!["apiserver".to_string()],
        timeout,
    );

    let supervisor =
        Supervisor::new(vec![apiserver_reg, kubelet_reg]).expect("supervisor creation succeeds");

    let (stop_handle, stop_receiver) = stop_channel();
    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    // Allow supervisor to start adapters and confirm readiness via polling
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !kubelet_service.is_running() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        kubelet_service.is_running(),
        "Kubelet service must be active after startup"
    );

    let report = kubelet_service.check_readiness().await.unwrap();
    assert!(report.is_healthy);
    assert!(report.node_ready);

    let client = kubelet_service.client();
    let node = client.get_node("test-node").await.expect("Node exists");
    assert_eq!(node["metadata"]["name"], "test-node");

    stop_handle.stop();
    let report = sup_handle.await.expect("supervisor task joins");
    assert!(matches!(report.cause, StopCause::Requested));
    assert!(!kubelet_service.is_running());
}
