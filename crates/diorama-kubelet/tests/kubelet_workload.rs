use std::net::IpAddr;
use std::sync::Arc;
use tempfile::TempDir;

use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use dioramalet::{KubeletConfigOptions, KubeletService, MockRuntimeProvider};

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
async fn test_manually_assigned_pod_runs_through_managed_provider() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new("managed-containerd"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime);
    kubelet.start().await.unwrap();

    let client = kubelet.client();

    // 1. Create a manually assigned pod
    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "managed-test-pod",
            "namespace": "default"
        },
        "spec": {
            "nodeName": "test-node",
            "containers": [
                {
                    "name": "nginx",
                    "image": "docker.io/library/nginx:1.27"
                }
            ]
        }
    });

    client.create_pod("default", pod_spec).await.unwrap();

    // 2. Reconcile pods assigned to this node
    let reconciler = kubelet.reconciler();
    let count = reconciler.reconcile_namespace("default").await.unwrap();
    assert_eq!(count, 1);

    // 3. Inspect pod status after reconciliation
    let updated_pod = client.get_pod("default", "managed-test-pod").await.unwrap();
    assert_eq!(updated_pod["status"]["phase"], "Running");
    assert_eq!(updated_pod["status"]["hostIP"], "192.0.2.1");
    assert_eq!(updated_pod["status"]["podIP"], "192.0.2.1");

    let conditions = updated_pod["status"]["conditions"].as_array().unwrap();
    for expected_cond in ["PodScheduled", "Initialized", "ContainersReady", "Ready"] {
        let cond = conditions
            .iter()
            .find(|c| c["type"] == expected_cond)
            .unwrap_or_else(|| panic!("missing condition {expected_cond}"));
        assert_eq!(cond["status"], "True");
    }

    let container_statuses = updated_pod["status"]["containerStatuses"]
        .as_array()
        .unwrap();
    assert_eq!(container_statuses.len(), 1);
    assert_eq!(container_statuses[0]["name"], "nginx");
    assert_eq!(container_statuses[0]["ready"], true);
    assert!(
        container_statuses[0]["containerID"]
            .as_str()
            .unwrap()
            .starts_with("managed-containerd://")
    );
}

#[tokio::test]
async fn test_manually_assigned_pod_runs_through_external_provider() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new("external-crio"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime);
    kubelet.start().await.unwrap();

    let client = kubelet.client();

    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "external-test-pod",
            "namespace": "default"
        },
        "spec": {
            "nodeName": "test-node",
            "containers": [
                {
                    "name": "alpine",
                    "image": "docker.io/library/alpine:3.20"
                }
            ]
        }
    });

    client.create_pod("default", pod_spec).await.unwrap();

    let reconciler = kubelet.reconciler();
    let count = reconciler.reconcile_namespace("default").await.unwrap();
    assert_eq!(count, 1);

    let updated_pod = client
        .get_pod("default", "external-test-pod")
        .await
        .unwrap();
    assert_eq!(updated_pod["status"]["phase"], "Running");

    let container_statuses = updated_pod["status"]["containerStatuses"]
        .as_array()
        .unwrap();
    assert_eq!(container_statuses.len(), 1);
    assert_eq!(container_statuses[0]["name"], "alpine");
    assert!(
        container_statuses[0]["containerID"]
            .as_str()
            .unwrap()
            .starts_with("external-crio://")
    );
}

#[tokio::test]
async fn test_unassigned_or_differently_assigned_pod_is_ignored() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new("containerd"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime);
    kubelet.start().await.unwrap();

    let client = kubelet.client();

    // Pod 1: No nodeName assigned
    let unscheduled = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "unscheduled-pod",
            "namespace": "default"
        },
        "spec": {
            "containers": [{"name": "pause", "image": "docker.io/portainer/pause:latest"}]
        }
    });
    client.create_pod("default", unscheduled).await.unwrap();

    // Pod 2: Assigned to another node
    let other_node_pod = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "other-node-pod",
            "namespace": "default"
        },
        "spec": {
            "nodeName": "other-worker-node",
            "containers": [{"name": "pause", "image": "docker.io/portainer/pause:latest"}]
        }
    });
    client.create_pod("default", other_node_pod).await.unwrap();

    let reconciler = kubelet.reconciler();
    let count = reconciler.reconcile_namespace("default").await.unwrap();
    assert_eq!(count, 0);

    let pod1 = client.get_pod("default", "unscheduled-pod").await.unwrap();
    assert!(pod1.get("status").is_none() || pod1["status"].get("phase").is_none());

    let pod2 = client.get_pod("default", "other-node-pod").await.unwrap();
    assert!(pod2.get("status").is_none() || pod2["status"].get("phase").is_none());
}
