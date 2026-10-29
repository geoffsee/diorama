#![allow(clippy::too_many_lines)]

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::TempDir;

use async_trait::async_trait;
use diorama_apiserver::{ApiserverConfig, ApiserverError, ApiserverService, KubernetesStorage};
use diorama_controller::webhook::{
    LoadBalancerClient, NodeSetterHandler, WebhookConfig, WebhookService,
    update_load_balancer_status_with_retry,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use serde_json::{Value, json};
use tokio::sync::Mutex;

fn setup_test_apiserver(
    dir: &TempDir,
    node_name: &str,
    lb_ip: &str,
    lb_enabled: bool,
) -> (Arc<ApiserverService>, WebhookService) {
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let datastore_dir = dir.path().join("datastore");

    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), node_name.to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir)).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    let apiserver_service = Arc::new(ApiserverService::new(apiserver_config, storage));

    let mut webhook_config = WebhookConfig::default_for_pki(&pki_dir, node_name, lb_ip, lb_enabled);
    webhook_config.port = 0; // ephemeral port for test isolation
    let webhook_service = WebhookService::new(webhook_config, apiserver_service.clone());

    (apiserver_service, webhook_service)
}

// --- Mock LoadBalancerClient for Fixture Oracle Parity ---

struct MockLbClient {
    get_responses: Mutex<Vec<Result<Value, ApiserverError>>>,
    patch_responses: Mutex<Vec<Result<Value, ApiserverError>>>,
    get_count: AtomicUsize,
    patch_count: AtomicUsize,
    recorded_patches: Mutex<Vec<(String, String, Value)>>,
}

impl MockLbClient {
    fn new(
        get_responses: Vec<Result<Value, ApiserverError>>,
        patch_responses: Vec<Result<Value, ApiserverError>>,
    ) -> Self {
        Self {
            get_responses: Mutex::new(get_responses),
            patch_responses: Mutex::new(patch_responses),
            get_count: AtomicUsize::new(0),
            patch_count: AtomicUsize::new(0),
            recorded_patches: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl LoadBalancerClient for MockLbClient {
    async fn get_service(&self, _namespace: &str, _name: &str) -> Result<Value, ApiserverError> {
        self.get_count.fetch_add(1, Ordering::SeqCst);
        let mut guard = self.get_responses.lock().await;
        if guard.is_empty() {
            Err(ApiserverError::NotFound {
                resource: "services".to_string(),
                name: "mock".to_string(),
            })
        } else {
            guard.remove(0)
        }
    }

    async fn patch_service_status(
        &self,
        namespace: &str,
        name: &str,
        status: Value,
    ) -> Result<Value, ApiserverError> {
        self.patch_count.fetch_add(1, Ordering::SeqCst);
        self.recorded_patches.lock().await.push((
            namespace.to_string(),
            name.to_string(),
            status.clone(),
        ));
        let mut guard = self.patch_responses.lock().await;
        if guard.is_empty() {
            Ok(json!({"status": status}))
        } else {
            guard.remove(0)
        }
    }
}

fn make_service_fixture(svc_type: &str, ingress_ip: Option<&str>) -> Value {
    let mut svc = json!({
        "metadata": {
            "name": "svc",
            "namespace": "default"
        },
        "spec": {
            "type": svc_type
        },
        "status": {}
    });
    if let Some(ip) = ingress_ip {
        svc["status"]["loadBalancer"] = json!({
            "ingress": [
                { "ip": ip }
            ]
        });
    }
    svc
}

#[tokio::test]
async fn test_fixture_oracle_parity_cases() {
    let lb_ip = "192.0.2.9";

    // Case 1: "assign" -> 1 get, 1 patch
    let client = MockLbClient::new(
        vec![Ok(make_service_fixture("LoadBalancer", None))],
        vec![Ok(json!({}))],
    );
    let res = update_load_balancer_status_with_retry(
        &client,
        "default",
        "svc",
        lb_ip,
        5,
        Duration::from_millis(1),
    )
    .await;
    assert!(res.is_ok());
    assert_eq!(client.get_count.load(Ordering::SeqCst), 1);
    assert_eq!(client.patch_count.load(Ordering::SeqCst), 1);
    let recorded = client.recorded_patches.lock().await;
    assert_eq!(
        recorded[0].2,
        json!({"status": {"loadBalancer": {"ingress": [{"ip": lb_ip}]}}})
    );

    // Case 2: "already_correct" -> 1 get, 0 patch
    let client = MockLbClient::new(
        vec![Ok(make_service_fixture("LoadBalancer", Some(lb_ip)))],
        vec![],
    );
    let res = update_load_balancer_status_with_retry(
        &client,
        "default",
        "svc",
        lb_ip,
        5,
        Duration::from_millis(1),
    )
    .await;
    assert!(res.is_ok());
    assert_eq!(client.get_count.load(Ordering::SeqCst), 1);
    assert_eq!(client.patch_count.load(Ordering::SeqCst), 0);

    // Case 3: "stale_type" -> 1 get (ClusterIP), 1 get (LoadBalancer), 1 patch
    let client = MockLbClient::new(
        vec![
            Ok(make_service_fixture("ClusterIP", None)),
            Ok(make_service_fixture("LoadBalancer", None)),
        ],
        vec![Ok(json!({}))],
    );
    let res = update_load_balancer_status_with_retry(
        &client,
        "default",
        "svc",
        lb_ip,
        5,
        Duration::from_millis(1),
    )
    .await;
    assert!(res.is_ok());
    assert_eq!(client.get_count.load(Ordering::SeqCst), 2);
    assert_eq!(client.patch_count.load(Ordering::SeqCst), 1);

    // Case 4: "get_failure" -> 1 get (Err), 1 get (Ok), 1 patch
    let client = MockLbClient::new(
        vec![
            Err(ApiserverError::Internal {
                reason: "network glitch".to_string(),
            }),
            Ok(make_service_fixture("LoadBalancer", None)),
        ],
        vec![Ok(json!({}))],
    );
    let res = update_load_balancer_status_with_retry(
        &client,
        "default",
        "svc",
        lb_ip,
        5,
        Duration::from_millis(1),
    )
    .await;
    assert!(res.is_ok());
    assert_eq!(client.get_count.load(Ordering::SeqCst), 2);
    assert_eq!(client.patch_count.load(Ordering::SeqCst), 1);

    // Case 5: "patch_failure" -> 1 get (Ok), 1 patch (Err), 1 get (Ok), 1 patch (Ok)
    let client = MockLbClient::new(
        vec![
            Ok(make_service_fixture("LoadBalancer", None)),
            Ok(make_service_fixture("LoadBalancer", None)),
        ],
        vec![
            Err(ApiserverError::Internal {
                reason: "conflict".to_string(),
            }),
            Ok(json!({})),
        ],
    );
    let res = update_load_balancer_status_with_retry(
        &client,
        "default",
        "svc",
        lb_ip,
        5,
        Duration::from_millis(1),
    )
    .await;
    assert!(res.is_ok());
    assert_eq!(client.get_count.load(Ordering::SeqCst), 2);
    assert_eq!(client.patch_count.load(Ordering::SeqCst), 2);

    // Case 6: "exhausted" -> 5 gets (all ClusterIP), 0 patches, error: "timed out waiting for the condition"
    let client = MockLbClient::new(
        vec![
            Ok(make_service_fixture("ClusterIP", None)),
            Ok(make_service_fixture("ClusterIP", None)),
            Ok(make_service_fixture("ClusterIP", None)),
            Ok(make_service_fixture("ClusterIP", None)),
            Ok(make_service_fixture("ClusterIP", None)),
        ],
        vec![],
    );
    let res = update_load_balancer_status_with_retry(
        &client,
        "default",
        "svc",
        lb_ip,
        5,
        Duration::from_millis(1),
    )
    .await;
    assert!(res.is_err());
    assert_eq!(client.get_count.load(Ordering::SeqCst), 5);
    assert_eq!(client.patch_count.load(Ordering::SeqCst), 0);
    let err_str = res.unwrap_err().to_string();
    assert!(
        err_str.contains("timed out waiting for the condition"),
        "Expected timeout error message, got: {err_str}"
    );
}

#[tokio::test]
async fn test_live_service_creation_and_custom_ip_assignment() {
    let temp = TempDir::new().unwrap();
    let custom_ip = "198.51.100.42";
    let (apiserver, webhook_service) = setup_test_apiserver(&temp, "test-node", custom_ip, true);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    webhook_service.check_prerequisites().await.unwrap();
    webhook_service.start().await.unwrap();

    let client = apiserver.admin_client();
    let ns = "test-lb-live";
    client.create_namespace(ns).await.unwrap();

    // 1. Create Service of type LoadBalancer: webhook admission receives CREATE, schedules status update
    let lb_svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "web-lb",
            "namespace": ns
        },
        "spec": {
            "type": "LoadBalancer",
            "ports": [{
                "port": 80,
                "targetPort": 8080
            }]
        }
    });

    let created = client.create_service(ns, lb_svc).await.unwrap();
    assert_eq!(created["spec"]["type"], "LoadBalancer");

    // Wait briefly for background status assignment to complete
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut assigned = false;
    while tokio::time::Instant::now() < deadline {
        let current = client.get_service(ns, "web-lb").await.unwrap();
        if let Some(ingress) = current
            .pointer("/status/loadBalancer/ingress")
            .and_then(Value::as_array)
            && ingress
                .first()
                .and_then(|i| i.get("ip"))
                .and_then(Value::as_str)
                == Some(custom_ip)
        {
            assigned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        assigned,
        "Service status must receive the custom LoadBalancer IP"
    );

    webhook_service.stop().await;
}

#[tokio::test]
async fn test_clusterip_to_loadbalancer_transition() {
    let temp = TempDir::new().unwrap();
    let lb_ip = "192.0.2.77";
    let (apiserver, webhook_service) = setup_test_apiserver(&temp, "test-node", lb_ip, true);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    webhook_service.check_prerequisites().await.unwrap();
    webhook_service.start().await.unwrap();

    let client = apiserver.admin_client();
    let ns = "test-lb-transition";
    client.create_namespace(ns).await.unwrap();

    // 1. Create Service as ClusterIP
    let cluster_svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "flip-svc",
            "namespace": ns
        },
        "spec": {
            "type": "ClusterIP",
            "ports": [{ "port": 80 }]
        }
    });

    let created = client.create_service(ns, cluster_svc).await.unwrap();
    assert_eq!(created["spec"]["type"], "ClusterIP");
    assert!(created.pointer("/status/loadBalancer/ingress").is_none());

    // 2. Transition Service to LoadBalancer on UPDATE
    let mut updated_svc = created.clone();
    updated_svc["spec"]["type"] = json!("LoadBalancer");

    let updated = client
        .update_service(ns, "flip-svc", updated_svc)
        .await
        .unwrap();
    assert_eq!(updated["spec"]["type"], "LoadBalancer");

    // Wait for the webhook background retry task to commit the status
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut assigned = false;
    while tokio::time::Instant::now() < deadline {
        let current = client.get_service(ns, "flip-svc").await.unwrap();
        if let Some(ingress) = current
            .pointer("/status/loadBalancer/ingress")
            .and_then(Value::as_array)
            && ingress
                .first()
                .and_then(|i| i.get("ip"))
                .and_then(Value::as_str)
                == Some(lb_ip)
        {
            assigned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        assigned,
        "Transitioned Service must receive the LoadBalancer external IP"
    );

    webhook_service.stop().await;
}

#[tokio::test]
async fn test_disabled_load_balancer_and_empty_address_behavior() {
    let temp = TempDir::new().unwrap();
    // Mode A: load_balancer = false
    let (apiserver, webhook_service) = setup_test_apiserver(&temp, "test-node", "192.0.2.1", false);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    webhook_service.check_prerequisites().await.unwrap();
    webhook_service.start().await.unwrap();

    let client = apiserver.admin_client();
    let ns = "test-lb-disabled";
    client.create_namespace(ns).await.unwrap();

    let svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "disabled-lb-svc",
            "namespace": ns
        },
        "spec": {
            "type": "LoadBalancer",
            "ports": [{ "port": 80 }]
        }
    });

    let created = client.create_service(ns, svc).await.unwrap();
    assert_eq!(created["spec"]["type"], "LoadBalancer");

    // Wait a brief window to ensure no status update is scheduled or written
    tokio::time::sleep(Duration::from_millis(300)).await;
    let fetched = client.get_service(ns, "disabled-lb-svc").await.unwrap();
    assert!(
        fetched.pointer("/status/loadBalancer/ingress").is_none(),
        "Disabled LoadBalancer mode must not assign ingress IP"
    );

    webhook_service.stop().await;

    // Mode B: empty load_balancer_ip
    let handler = NodeSetterHandler::new("test-node", "", true);
    let req = json!({
        "uid": "req-empty-ip",
        "kind": { "group": "", "version": "v1", "kind": "Service" },
        "operation": "CREATE",
        "object": {
            "metadata": { "name": "empty-ip-svc", "namespace": "default" },
            "spec": { "type": "LoadBalancer" }
        }
    });
    let (patch, scheduled) = handler.evaluate_mutation(&req).await.unwrap();
    assert!(patch.is_none());
    assert!(
        !scheduled,
        "Empty load_balancer_ip must not schedule status update"
    );
}

#[tokio::test]
async fn test_dry_run_performs_no_writes_and_no_locks() {
    let handler = NodeSetterHandler::new("test-node", "192.0.2.9", true);

    let dry_run_req = json!({
        "uid": "req-dry-run",
        "kind": { "group": "", "version": "v1", "kind": "Service" },
        "operation": "CREATE",
        "dryRun": true,
        "object": {
            "metadata": { "name": "dry-svc", "namespace": "default" },
            "spec": { "type": "LoadBalancer" }
        }
    });

    let (patch, scheduled) = handler.evaluate_mutation(&dry_run_req).await.unwrap();
    assert!(patch.is_none());
    assert!(
        !scheduled,
        "dry-run request must not schedule status update"
    );
    assert!(
        handler.locks().lock().await.is_empty(),
        "dry-run must not acquire locks"
    );
}

#[tokio::test]
async fn test_concurrent_requests_deduplication_and_no_recursion() {
    let client = Arc::new(MockLbClient::new(
        vec![
            Ok(make_service_fixture("LoadBalancer", None)),
            Ok(make_service_fixture("LoadBalancer", None)),
        ],
        vec![Ok(json!({}))],
    ));

    let handler = NodeSetterHandler::new("test-node", "192.0.2.9", true)
        .with_client(client.clone())
        .with_retry_params(5, Duration::from_millis(10), Duration::from_millis(50));

    let req = json!({
        "uid": "req-dup",
        "kind": { "group": "", "version": "v1", "kind": "Service" },
        "operation": "CREATE",
        "object": {
            "metadata": { "name": "dup-svc", "namespace": "default" },
            "spec": { "type": "LoadBalancer" }
        }
    });

    // 1. First request acquires lock and schedules update
    let (patch1, scheduled1) = handler.evaluate_mutation(&req).await.unwrap();
    assert!(patch1.is_none());
    assert!(scheduled1, "First request must schedule update");

    // 2. Immediate duplicate request sees lock already held, drops without scheduling duplicate task
    let (patch2, scheduled2) = handler.evaluate_mutation(&req).await.unwrap();
    assert!(patch2.is_none());
    assert!(
        !scheduled2,
        "Duplicate concurrent request must NOT schedule second update"
    );

    // 3. Wait for the background task and lock release delay to finish
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        handler.locks().lock().await.is_empty(),
        "Lock must be released after completion"
    );

    // 4. Verify patch_service_status writes to status without mutating admission recursion:
    // Only 1 patch was issued, not multiple
    assert_eq!(client.patch_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_restart_and_address_change_characterization_without_background_controller() {
    let temp = TempDir::new().unwrap();
    let initial_ip = "192.0.2.10";
    let (apiserver, webhook_service_1) = setup_test_apiserver(&temp, "test-node", initial_ip, true);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    webhook_service_1.check_prerequisites().await.unwrap();
    webhook_service_1.start().await.unwrap();

    let client = apiserver.admin_client();
    let ns = "test-lb-restart";
    client.create_namespace(ns).await.unwrap();

    // 1. Create a service with initial IP
    let svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "static-svc",
            "namespace": ns
        },
        "spec": {
            "type": "LoadBalancer",
            "ports": [{ "port": 80 }]
        }
    });
    client.create_service(ns, svc).await.unwrap();

    // Wait for initial IP assignment
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let current = client.get_service(ns, "static-svc").await.unwrap();
        if let Some(ingress) = current
            .pointer("/status/loadBalancer/ingress")
            .and_then(Value::as_array)
            && ingress
                .first()
                .and_then(|i| i.get("ip"))
                .and_then(Value::as_str)
                == Some(initial_ip)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 2. Restart webhook service with a NEW address (e.g. 192.0.2.99)
    webhook_service_1.stop().await;

    let pki_dir = temp.path().join("pki");
    let new_ip = "192.0.2.99";
    let mut new_config = WebhookConfig::default_for_pki(&pki_dir, "test-node", new_ip, true);
    new_config.port = 0;
    let webhook_service_2 = WebhookService::new(new_config, apiserver.clone());
    webhook_service_2.start().await.unwrap();

    // 3. Confirm that WITHOUT an update event, the existing service retains the initial IP
    // (Characterizing that diorama does NOT have an unsolicited background reconciliation controller)
    tokio::time::sleep(Duration::from_millis(300)).await;
    let existing = client.get_service(ns, "static-svc").await.unwrap();
    let retained_ip = existing
        .pointer("/status/loadBalancer/ingress/0/ip")
        .and_then(Value::as_str);
    assert_eq!(
        retained_ip,
        Some(initial_ip),
        "Without an update event, existing Service must retain its initial IP without background mutation"
    );

    // 4. When an UPDATE occurs (e.g. updating metadata label), the admission hook triggers
    // and updates the LoadBalancer status to the new IP!
    let mut updated_svc = existing.clone();
    updated_svc["metadata"]["labels"] = json!({"reconfigured": "true"});
    client
        .update_service(ns, "static-svc", updated_svc)
        .await
        .unwrap();

    let deadline2 = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut new_ip_assigned = false;
    while tokio::time::Instant::now() < deadline2 {
        let current = client.get_service(ns, "static-svc").await.unwrap();
        if let Some(ingress) = current
            .pointer("/status/loadBalancer/ingress")
            .and_then(Value::as_array)
            && ingress
                .first()
                .and_then(|i| i.get("ip"))
                .and_then(Value::as_str)
                == Some(new_ip)
        {
            new_ip_assigned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        new_ip_assigned,
        "Once updated, the Service status must be updated to the new LoadBalancer IP"
    );

    webhook_service_2.stop().await;
}

#[tokio::test]
async fn test_stale_resource_version_detection_and_conflict() {
    let temp = TempDir::new().unwrap();
    let (apiserver, _webhook_service) = setup_test_apiserver(&temp, "test-node", "192.0.2.1", true);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    let client = apiserver.admin_client();
    let ns = "test-stale-rv";
    client.create_namespace(ns).await.unwrap();

    let svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "rv-svc", "namespace": ns },
        "spec": { "type": "LoadBalancer", "ports": [{ "port": 80 }] }
    });
    let created = client.create_service(ns, svc).await.unwrap();
    let initial_rv = created
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
        .unwrap();

    // Modify the service to bump its resourceVersion
    let mut modified = created.clone();
    modified["metadata"]["labels"] = json!({"foo": "bar"});
    let updated = client.update_service(ns, "rv-svc", modified).await.unwrap();
    let new_rv = updated
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
        .unwrap();
    assert_ne!(initial_rv, new_rv);

    // Attempting to patch status using the STALE initial_rv must fail with Conflict
    let stale_patch = json!({
        "metadata": { "resourceVersion": initial_rv },
        "status": {
            "loadBalancer": {
                "ingress": [{ "ip": "1.2.3.4" }]
            }
        }
    });
    let patch_res = client.patch_service_status(ns, "rv-svc", stale_patch).await;
    assert!(patch_res.is_err(), "Stale resourceVersion must be rejected");

    // Patching with the current new_rv must succeed
    let fresh_patch = json!({
        "metadata": { "resourceVersion": new_rv },
        "status": {
            "loadBalancer": {
                "ingress": [{ "ip": "1.2.3.4" }]
            }
        }
    });
    let patch_res = client.patch_service_status(ns, "rv-svc", fresh_patch).await;
    assert!(patch_res.is_ok(), "Fresh resourceVersion must succeed");
}
