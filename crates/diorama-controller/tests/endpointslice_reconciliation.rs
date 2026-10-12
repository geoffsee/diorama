use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_controller::workload::WorkloadManager;
use diorama_controller::{ControllerManagerConfig, ControllerManagerService};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use serde_json::{Value, json};
use tempfile::TempDir;

fn setup_test_controller(dir: &TempDir) -> ControllerManagerService {
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let datastore_dir = dir.path().join("datastore");

    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "test-node".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir)).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    let apiserver_service = ApiserverService::new(apiserver_config, storage);

    let controller_config = ControllerManagerConfig::default_for_pki(&pki_dir, node_ip);
    let apiserver_arc = Arc::new(apiserver_service);

    ControllerManagerService::new(controller_config, apiserver_arc)
}

#[tokio::test]
async fn test_endpointslice_addition_and_latency_bound() {
    let temp = TempDir::new().unwrap();
    let controller_svc = setup_test_controller(&temp);
    controller_svc.start().await.unwrap();

    let client = controller_svc.client();
    let wm = controller_svc.workload_manager();
    let ns = "test-endpoints-latency";

    client.create_namespace(ns).await.unwrap();

    let service = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "web-svc", "namespace": ns },
        "spec": {
            "selector": { "app": "web" },
            "ports": [
                { "name": "http", "port": 80, "protocol": "TCP" },
                { "name": "https", "port": 443, "protocol": "TCP" },
            ]
        }
    });
    client.create_service(ns, service).await.unwrap();

    // Initial reconciliation: 0 endpoints
    let summary = wm.reconcile_namespace(ns).await.unwrap();
    assert_eq!(summary.endpointslices_reconciled, 1);
    assert_eq!(summary.endpoints_reconciled, 1);

    let initial_slice = client.get_endpointslice(ns, "web-svc-1").await.unwrap();
    let endpoints = initial_slice
        .get("endpoints")
        .and_then(Value::as_array)
        .unwrap();
    assert!(endpoints.is_empty());

    // Add Pod 1 and measure latency bound (< 500ms << historical 5s batch delay)
    let pod1 = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "web-pod-1", "namespace": ns, "labels": { "app": "web" } },
        "spec": { "containers": [{ "name": "c", "image": "test:latest" }] },
        "status": {
            "phase": "Running",
            "podIP": "10.244.0.10",
            "conditions": [{ "type": "Ready", "status": "True" }]
        }
    });
    client.create_pod(ns, pod1).await.unwrap();

    let start = Instant::now();
    let summary = wm.reconcile_namespace(ns).await.unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "EndpointSlice update must be immediate (<500ms), took {elapsed:?}"
    );
    assert_eq!(summary.endpointslices_reconciled, 1);

    let slice = client.get_endpointslice(ns, "web-svc-1").await.unwrap();
    let eps = slice.get("endpoints").and_then(Value::as_array).unwrap();
    assert_eq!(eps.len(), 1);
    assert_eq!(eps[0]["addresses"][0], "10.244.0.10");
    assert_eq!(eps[0]["conditions"]["ready"], true);
    assert_eq!(eps[0]["conditions"]["serving"], true);
    assert_eq!(eps[0]["conditions"]["terminating"], false);

    // Verify core/v1 Endpoints
    let ep = client.get_endpoints(ns, "web-svc").await.unwrap();
    let subsets = ep.get("subsets").and_then(Value::as_array).unwrap();
    assert_eq!(subsets.len(), 1);
    let addrs = subsets[0]["addresses"].as_array().unwrap();
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0]["ip"], "10.244.0.10");
}

#[tokio::test]
async fn test_endpointslice_readiness_churn_and_cascading_gc() {
    let temp = TempDir::new().unwrap();
    let controller_svc = setup_test_controller(&temp);
    controller_svc.start().await.unwrap();

    let client = controller_svc.client();
    let wm = controller_svc.workload_manager();
    let ns = "test-endpoints-churn";

    client.create_namespace(ns).await.unwrap();

    let service = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "web-svc", "namespace": ns },
        "spec": {
            "selector": { "app": "web" },
            "ports": [{ "port": 80, "protocol": "TCP" }]
        }
    });
    client.create_service(ns, service).await.unwrap();

    // Create 2 ready pods
    for i in 1..=2 {
        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": format!("web-pod-{i}"), "namespace": ns, "labels": { "app": "web" } },
            "spec": { "containers": [{ "name": "c", "image": "test:latest" }] },
            "status": {
                "phase": "Running",
                "podIP": format!("10.244.0.1{i}"),
                "conditions": [{ "type": "Ready", "status": "True" }]
            }
        });
        client.create_pod(ns, pod).await.unwrap();
    }
    wm.reconcile_namespace(ns).await.unwrap();

    // Mark Pod 2 unready
    let mut pod2 = client.get_pod(ns, "web-pod-2").await.unwrap();
    pod2["status"]["conditions"] = json!([{ "type": "Ready", "status": "False" }]);
    client.update_pod(ns, "web-pod-2", pod2).await.unwrap();
    wm.reconcile_namespace(ns).await.unwrap();

    let slice = client.get_endpointslice(ns, "web-svc-1").await.unwrap();
    let eps = slice.get("endpoints").and_then(Value::as_array).unwrap();
    assert_eq!(eps.len(), 2);
    assert_eq!(eps[0]["conditions"]["ready"], true);
    assert_eq!(eps[1]["conditions"]["ready"], false);

    // Verify core/v1 Endpoints has separated ready vs notReady
    let ep = client.get_endpoints(ns, "web-svc").await.unwrap();
    let subsets = ep.get("subsets").and_then(Value::as_array).unwrap();
    assert_eq!(subsets[0]["addresses"].as_array().unwrap().len(), 1);
    assert_eq!(subsets[0]["notReadyAddresses"].as_array().unwrap().len(), 1);

    // Delete Pod 1 then Pod 2
    client.delete_pod(ns, "web-pod-1").await.unwrap();
    wm.reconcile_namespace(ns).await.unwrap();
    client.delete_pod(ns, "web-pod-2").await.unwrap();
    wm.reconcile_namespace(ns).await.unwrap();

    let slice = client.get_endpointslice(ns, "web-svc-1").await.unwrap();
    assert!(
        slice
            .get("endpoints")
            .and_then(Value::as_array)
            .unwrap()
            .is_empty()
    );

    // Delete Service: cascading garbage collection removes EndpointSlice and Endpoints
    client.delete_service(ns, "web-svc").await.unwrap();
    let summary = wm.reconcile_namespace(ns).await.unwrap();
    assert!(summary.garbage_collected >= 2);

    assert!(client.get_endpointslice(ns, "web-svc-1").await.is_err());
    assert!(client.get_endpoints(ns, "web-svc").await.is_err());
}

#[tokio::test]
async fn test_controller_restart_and_backend_churn_without_batch_delay() {
    let temp = TempDir::new().unwrap();
    let controller_svc = setup_test_controller(&temp);
    controller_svc.start().await.unwrap();

    let client = controller_svc.client();
    let ns = "test-churn-recovery";

    client.create_namespace(ns).await.unwrap();

    let service = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "churn-svc", "namespace": ns },
        "spec": {
            "selector": { "app": "churn" },
            "ports": [{ "port": 8080, "protocol": "TCP" }]
        }
    });
    client.create_service(ns, service).await.unwrap();

    // 1. Backend churn: create 5 pods in rapid succession
    for i in 0..5 {
        let is_ready = i % 2 == 0;
        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": format!("churn-pod-{i}"),
                "namespace": ns,
                "labels": { "app": "churn" }
            },
            "spec": { "containers": [{ "name": "c", "image": "test:latest" }] },
            "status": {
                "phase": "Running",
                "podIP": format!("10.244.1.{i}"),
                "conditions": [{ "type": "Ready", "status": if is_ready { "True" } else { "False" } }]
            }
        });
        client.create_pod(ns, pod).await.unwrap();
    }

    let wm = WorkloadManager::new(Arc::new(client.clone()));
    let summary = wm.reconcile_namespace(ns).await.unwrap();
    assert_eq!(summary.endpointslices_reconciled, 1);
    assert_eq!(summary.endpoints_reconciled, 1);

    // 2. Churn burst: delete 2 pods, flip 1 pod readiness
    client.delete_pod(ns, "churn-pod-1").await.unwrap();
    client.delete_pod(ns, "churn-pod-3").await.unwrap();

    let mut pod0 = client.get_pod(ns, "churn-pod-0").await.unwrap();
    pod0["status"]["conditions"] = json!([{ "type": "Ready", "status": "False" }]);
    client.update_pod(ns, "churn-pod-0", pod0).await.unwrap();

    // 3. Simulate controller restart by instantiating a fresh WorkloadManager
    let restarted_wm = WorkloadManager::new(Arc::new(client.clone()));
    let start = Instant::now();
    let summary = restarted_wm.reconcile_namespace(ns).await.unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(500),
        "Restarted controller must reconcile immediately without batch delay, took {elapsed:?}"
    );
    assert_eq!(summary.endpointslices_reconciled, 1);

    // Verify converged state after churn and restart
    let slice = client.get_endpointslice(ns, "churn-svc-1").await.unwrap();
    let eps = slice.get("endpoints").and_then(Value::as_array).unwrap();
    assert_eq!(eps.len(), 3);
    assert_eq!(eps[0]["targetRef"]["name"], "churn-pod-0");
    assert_eq!(eps[0]["conditions"]["ready"], false);
    assert_eq!(eps[1]["targetRef"]["name"], "churn-pod-2");
    assert_eq!(eps[1]["conditions"]["ready"], true);
    assert_eq!(eps[2]["targetRef"]["name"], "churn-pod-4");
    assert_eq!(eps[2]["conditions"]["ready"], true);

    // 4. Verify batch delay rejection per KS-29 / PR #111
    let bad_config = ControllerManagerConfig {
        endpointslice_updates_batch_period: Duration::from_secs(5),
        ..Default::default()
    };
    let err = bad_config.validate_batch_periods().unwrap_err();
    assert!(
        err.to_string()
            .contains("batch period 5s must be 0s per KS-29 / PR #111")
    );
}

#[tokio::test]
async fn test_service_without_selector_is_skipped() {
    let temp = TempDir::new().unwrap();
    let controller_svc = setup_test_controller(&temp);
    controller_svc.start().await.unwrap();

    let client = controller_svc.client();
    let wm = controller_svc.workload_manager();
    let ns = "test-headless-manual";

    client.create_namespace(ns).await.unwrap();

    let headless_manual = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "headless-manual", "namespace": ns },
        "spec": {
            "clusterIP": "None",
            "ports": [{ "port": 9000, "protocol": "TCP" }]
        }
    });
    client.create_service(ns, headless_manual).await.unwrap();

    let summary = wm.reconcile_namespace(ns).await.unwrap();
    assert_eq!(summary.endpointslices_reconciled, 0);
    assert_eq!(summary.endpoints_reconciled, 0);
    assert!(summary.errors.is_empty());

    assert!(
        client
            .get_endpointslice(ns, "headless-manual-1")
            .await
            .is_err()
    );
    assert!(client.get_endpoints(ns, "headless-manual").await.is_err());
}
