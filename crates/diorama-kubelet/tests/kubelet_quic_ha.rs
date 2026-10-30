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

#[tokio::test]
async fn test_remote_worker_kubelet_registers_node_and_reconciles_over_quic() {
    use diorama_apiserver::KubernetesApiClient;
    use diorama_datastore::{DatastoreClient, start_quic_server};

    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let seed_pki = temp.path().join("seed-pki");
    std::fs::create_dir_all(&seed_pki).unwrap();
    ClusterPki::new(ClusterPkiConfig::new(
        seed_pki.clone(),
        "controller-1".to_string(),
        node_ip,
    ))
    .reconcile()
    .unwrap();

    let seed_cfg = DatastoreConfig::new(temp.path().join("seed-ds")).with_client_tls(
        seed_pki.join("datastore-ca.crt"),
        seed_pki.join("datastore-server.crt"),
        seed_pki.join("datastore-server.key"),
    );
    let (seed_engine, _) = DatastoreEngine::open(seed_cfg).unwrap();
    let seed_peer_addr = start_quic_server(
        "127.0.0.1:0".parse().unwrap(),
        seed_pki.join("datastore-server.crt"),
        seed_pki.join("datastore-server.key"),
        seed_engine.clone(),
    )
    .await
    .unwrap();

    let seed_storage = KubernetesStorage::new(seed_engine.client(), "/registry");
    let apiserver = Arc::new(ApiserverService::new(
        ApiserverConfig::default_for_pki(&seed_pki, node_ip),
        seed_storage,
    ));
    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let ctrl_client = apiserver.admin_client();

    // Issue worker join material and install on worker node without any local ApiserverService
    let worker_material = ClusterPki::issue_worker_join_material(
        &seed_pki,
        "worker-remote-1",
        node_ip,
        "https://127.0.0.1:6443",
    )
    .unwrap();
    let worker_pki = temp.path().join("worker-pki");
    ClusterPki::install_worker_join_material(&worker_pki, &worker_material).unwrap();

    let remote_ds = DatastoreClient::new_remote(
        seed_peer_addr,
        Some(worker_pki.join("datastore-server.crt")),
        Some(worker_pki.join("datastore-server.key")),
    );
    let remote_storage = KubernetesStorage::new(remote_ds, "/registry");
    let worker_node_client = Arc::new(KubernetesApiClient::new_remote_node(
        remote_storage,
        "worker-remote-1",
        worker_pki.join("ca.crt"),
    ));

    let worker_kubelet_dir = temp.path().join("worker-kubelet");
    std::fs::create_dir_all(&worker_kubelet_dir).unwrap();
    let worker_opts = KubeletConfigOptions::default_for_pki(
        &worker_pki,
        "worker-remote-1",
        "127.0.0.1",
        &worker_kubelet_dir,
    );
    let worker_runtime = Arc::new(MockRuntimeProvider::new("managed-containerd"));
    let worker_kubelet =
        KubeletService::from_client(worker_opts, worker_node_client, worker_runtime)
            .with_multi_node(true);

    worker_kubelet.start().await.unwrap();

    // Verify the controller sees the Node object registered by the remote worker kubelet
    let node_doc = ctrl_client.get_node("worker-remote-1").await.unwrap();
    assert_eq!(node_doc["metadata"]["name"], "worker-remote-1");

    // Create a pod assigned to worker-remote-1 and reconcile it from the remote worker
    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "worker-pod",
            "namespace": "default"
        },
        "spec": {
            "nodeName": "worker-remote-1",
            "containers": [
                {
                    "name": "web",
                    "image": "docker.io/library/nginx:1.27"
                }
            ]
        }
    });
    ctrl_client.create_pod("default", pod_spec).await.unwrap();

    let rep = worker_kubelet.reconcile_once().await.unwrap();
    assert_eq!(rep.synced, 1);

    let pod_after = ctrl_client.get_pod("default", "worker-pod").await.unwrap();
    assert_eq!(pod_after["status"]["phase"], "Running");
}

#[tokio::test]
async fn test_streaming_logs_follow_and_interactive_exec_over_quic() {
    use diorama_apiserver::{ExecStreamInput, ExecStreamOutput};

    let temp = TempDir::new().unwrap();
    let (kubelet1, kubelet2, router) = setup_two_node_kubelets(temp.path()).await;
    let client = kubelet1.client();

    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "stream-pod",
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
    kubelet2.reconcile_once().await.unwrap();
    let running_pod = client.get_pod("default", "stream-pod").await.unwrap();

    // 1. Stream logs (kubectl logs -f) over tokio-quiche (/pods/log/stream)
    let mut log_rx = router
        .stream_pod_log(
            &running_pod,
            &PodLogOptions {
                follow: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let first_chunk = tokio::time::timeout(std::time::Duration::from_secs(3), log_rx.recv())
        .await
        .expect("timed out waiting for streamed log chunk")
        .expect("log stream closed")
        .unwrap();
    assert!(first_chunk.contains("container app is running in"));

    // 2. Interactive exec (kubectl exec -it) over tokio-quiche (/pods/exec/stream)
    let (in_tx, mut out_rx) = router
        .stream_exec_in_pod(&running_pod, "app", &["cat".to_string()], true)
        .await
        .unwrap();

    in_tx
        .send(ExecStreamInput::Resize {
            width: 120,
            height: 40,
        })
        .await
        .unwrap();
    let resize_ack = tokio::time::timeout(std::time::Duration::from_secs(3), out_rx.recv())
        .await
        .expect("timed out waiting for ResizeAck")
        .expect("exec stream closed");
    assert_eq!(
        resize_ack,
        ExecStreamOutput::ResizeAck {
            width: 120,
            height: 40
        }
    );

    in_tx
        .send(ExecStreamInput::Stdin(b"hello-interactive-tty\n".to_vec()))
        .await
        .unwrap();
    let stdout_frame = tokio::time::timeout(std::time::Duration::from_secs(3), out_rx.recv())
        .await
        .expect("timed out waiting for interactive stdout")
        .expect("exec stream closed");
    assert_eq!(
        stdout_frame,
        ExecStreamOutput::Stdout(b"hello-interactive-tty\n".to_vec())
    );

    in_tx.send(ExecStreamInput::Close).await.unwrap();
    let exit_frame = tokio::time::timeout(std::time::Duration::from_secs(3), out_rx.recv())
        .await
        .expect("timed out waiting for Exit")
        .expect("exec stream closed");
    assert_eq!(exit_frame, ExecStreamOutput::Exit(0));
}
