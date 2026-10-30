use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

use diorama_apiserver::{
    ApiserverConfig, ApiserverService, ClusterPodRouter, KubernetesStorage, PodExec, PodLogOptions,
    PodLogReader,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use dioramalet::{KubeletConfigOptions, KubeletService, MockRuntimeProvider};

async fn setup_two_node_kubelets(
    root: &Path,
) -> (KubeletService, KubeletService, ClusterPodRouter) {
    let node_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let pki_dir1 = root.join("pki-1");
    let pki_dir2 = root.join("pki-2");
    std::fs::create_dir_all(&pki_dir1).unwrap();
    std::fs::create_dir_all(&pki_dir2).unwrap();

    ClusterPki::new(ClusterPkiConfig::new(
        pki_dir1.clone(),
        "node-1".to_string(),
        node_ip,
    ))
    .reconcile()
    .unwrap();
    ClusterPki::new(ClusterPkiConfig::new(
        pki_dir2.clone(),
        "node-2".to_string(),
        node_ip,
    ))
    .reconcile()
    .unwrap();

    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(root.join("ds"))).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    let apiserver = Arc::new(ApiserverService::new(
        ApiserverConfig::default_for_pki(&pki_dir1, node_ip),
        storage.clone(),
    ));
    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    let kubelet_dir1 = root.join("kubelet-1");
    let kubelet_dir2 = root.join("kubelet-2");
    std::fs::create_dir_all(&kubelet_dir1).unwrap();
    std::fs::create_dir_all(&kubelet_dir2).unwrap();

    let opts1 =
        KubeletConfigOptions::default_for_pki(&pki_dir1, "node-1", "127.0.0.1", &kubelet_dir1);
    let opts2 =
        KubeletConfigOptions::default_for_pki(&pki_dir2, "node-2", "127.0.0.1", &kubelet_dir2);

    let runtime1 = Arc::new(MockRuntimeProvider::new("managed-containerd"));
    let runtime2 = Arc::new(MockRuntimeProvider::new("managed-containerd"));

    let kubelet1 = KubeletService::new(opts1, apiserver.clone(), runtime1).with_multi_node(true);
    let kubelet2 = KubeletService::new(opts2, apiserver, runtime2).with_multi_node(true);

    kubelet1.start().await.unwrap();
    kubelet2.start().await.unwrap();

    let quic_addr: SocketAddr = kubelet2
        .start_quic_proxy_server(
            "127.0.0.1:0".parse().unwrap(),
            pki_dir2.join("kube-apiserver.crt"),
            pki_dir2.join("kube-apiserver.key"),
        )
        .await
        .unwrap();

    let router = ClusterPodRouter::new("node-1", storage)
        .with_local_log_reader(Arc::new(kubelet1.log_source()))
        .with_local_exec(Arc::new(kubelet1.exec_source()))
        .with_client_tls(
            pki_dir1.join("kube-apiserver.crt"),
            pki_dir1.join("kube-apiserver.key"),
        );
    router.register_peer_endpoint("node-2", quic_addr);

    (kubelet1, kubelet2, router)
}

#[tokio::test]
async fn test_multi_node_kubelet_quic_log_and_exec_routing_and_orphan_isolation() {
    let temp = TempDir::new().unwrap();
    let (kubelet1, kubelet2, router) = setup_two_node_kubelets(temp.path()).await;
    let client = kubelet1.client();

    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "remote-pod",
            "namespace": "default"
        },
        "spec": {
            "nodeName": "node-2",
            "containers": [
                {
                    "name": "app",
                    "image": "docker.io/library/nginx:1.27"
                }
            ]
        }
    });
    client.create_pod("default", pod_spec).await.unwrap();

    // Reconcile on node-1: should NOT sync node-2's pod
    let rep1 = kubelet1.reconcile_once().await.unwrap();
    assert_eq!(rep1.synced, 0);

    // Reconcile on node-2: should sync remote-pod
    let rep2 = kubelet2.reconcile_once().await.unwrap();
    assert_eq!(rep2.synced, 1);

    let running_pod = client.get_pod("default", "remote-pod").await.unwrap();
    assert_eq!(running_pod["status"]["phase"], "Running");

    // Proxy PodLogReader from node-1 to node-2 over tokio-quiche
    let logs = router
        .read_pod_log(&running_pod, &PodLogOptions::default())
        .await
        .unwrap();
    assert!(logs.contains("container app is running in"));

    // Proxy PodExec from node-1 to node-2 over tokio-quiche
    let exec_res = router
        .exec_in_pod(
            &running_pod,
            "app",
            &["echo".to_string(), "hello-ha".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(exec_res.exit_code, 0);
    let stdout_str = String::from_utf8_lossy(&exec_res.stdout);
    assert!(stdout_str.contains("hello-ha"));
}
