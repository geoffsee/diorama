use std::net::IpAddr;
use std::sync::Arc;

use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_controller::webhook::NodeSetterHandler;
use diorama_controller::{ControllerManagerConfig, ControllerManagerService};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use serde_json::json;
use tempfile::TempDir;

#[tokio::test]
async fn test_controller_leader_election_and_multi_node_admission_bypass() {
    let dir = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let datastore_dir = dir.path().join("datastore");

    ClusterPki::new(ClusterPkiConfig::new(
        pki_dir.clone(),
        "node-1".to_string(),
        node_ip,
    ))
    .reconcile()
    .unwrap();

    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir)).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    let apiserver = Arc::new(ApiserverService::new(
        ApiserverConfig::default_for_pki(&pki_dir, node_ip),
        storage,
    ));

    let cfg = ControllerManagerConfig::default_for_pki(&pki_dir, node_ip);

    let cm1 = ControllerManagerService::new(cfg.clone(), apiserver.clone())
        .with_leader_election("node-1", 30);
    let cm2 =
        ControllerManagerService::new(cfg, apiserver.clone()).with_leader_election("node-2", 30);

    cm1.start().await.unwrap();
    cm2.start().await.unwrap();

    // cm1 acquires the kube-system/kube-controller-manager Lease
    assert!(cm1.try_acquire_or_renew_leader_lease().await.unwrap());
    // cm2 sees cm1's unexpired lease and yields
    assert!(!cm2.try_acquire_or_renew_leader_lease().await.unwrap());
    // cm2 reconcile_all returns empty while standby
    let summaries = cm2.reconcile_all().await.unwrap();
    assert_eq!(summaries.len(), 0);

    // Verify NodeSetterHandler bypasses single-node Pod/PVC/Job hardcoding in multi-node mode
    let single_node_handler = NodeSetterHandler::new("node-1", "192.0.2.1", true);
    let multi_node_handler =
        NodeSetterHandler::new("node-1", "192.0.2.1", true).with_multi_node(true);

    let pod_req = json!({
        "kind": { "kind": "Pod" },
        "object": { "spec": {} }
    });
    let (single_patch, _) = single_node_handler
        .evaluate_mutation(&pod_req)
        .await
        .unwrap();
    assert!(single_patch.is_some());

    let (multi_patch, _) = multi_node_handler
        .evaluate_mutation(&pod_req)
        .await
        .unwrap();
    assert!(multi_patch.is_none());
}
