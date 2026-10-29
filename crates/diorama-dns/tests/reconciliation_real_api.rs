use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

use diorama_apiserver::{
    ApiserverConfig, ApiserverService, KubernetesApiClient, KubernetesStorage,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_dns::{
    COREDNS_CLUSTER_ROLE_NAME, COREDNS_CONFIGMAP_NAME, COREDNS_DEPLOYMENT_NAME, COREDNS_NAMESPACE,
    COREDNS_SERVICE_ACCOUNT_NAME, COREDNS_SERVICE_NAME, CoreDnsAdapter, CoreDnsConfig,
    CoreDnsService, DnsError, DnsReconciler,
};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_supervisor::{StopCause, Supervisor, stop_channel};
use serde_json::json;

fn setup_test_cluster(dir: &TempDir) -> (ApiserverService, KubernetesApiClient) {
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
    let client = apiserver_service.admin_client();

    (apiserver_service, client)
}

#[tokio::test]
async fn test_cold_startup_reconciliation_real_api() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    // Ensure namespace exists
    let _ = client.create_namespace(COREDNS_NAMESPACE).await;

    let config = CoreDnsConfig::new()
        .with_container_mode(false)
        .with_disable_ipv6(true);
    let reconciler = DnsReconciler::new(&config);

    // 1. Cold start reconciliation
    let report = reconciler.reconcile(&client).await.unwrap();
    assert!(report.config_map_created, "ConfigMap must be created");
    assert!(
        report.service_account_created,
        "ServiceAccount must be created"
    );
    assert!(report.cluster_role_created, "ClusterRole must be created");
    assert!(
        report.cluster_role_binding_created,
        "ClusterRoleBinding must be created"
    );
    assert!(report.service_created, "Service must be created");
    assert!(report.deployment_created, "Deployment must be created");

    // 2. Verify ConfigMap in real API
    let cm = client
        .get_configmap(COREDNS_NAMESPACE, COREDNS_CONFIGMAP_NAME)
        .await
        .unwrap();
    assert_eq!(
        cm["metadata"]["name"].as_str().unwrap(),
        COREDNS_CONFIGMAP_NAME
    );
    let corefile = cm["data"]["Corefile"].as_str().unwrap();
    assert!(corefile.contains("in-addr.arpa"));
    assert!(!corefile.contains("ip6.arpa"));

    // 3. Verify ServiceAccount in real API
    let sa = client
        .get_service_account(COREDNS_NAMESPACE, COREDNS_SERVICE_ACCOUNT_NAME)
        .await
        .unwrap();
    assert_eq!(
        sa["metadata"]["name"].as_str().unwrap(),
        COREDNS_SERVICE_ACCOUNT_NAME
    );

    // 4. Verify ClusterRole and ClusterRoleBinding in real API
    let cr = client
        .get_cluster_role(COREDNS_CLUSTER_ROLE_NAME)
        .await
        .unwrap();
    assert_eq!(cr.name, COREDNS_CLUSTER_ROLE_NAME);
    let crb = client
        .get_cluster_role_binding(COREDNS_CLUSTER_ROLE_NAME)
        .await
        .unwrap();
    assert_eq!(crb.name, COREDNS_CLUSTER_ROLE_NAME);

    // 5. Verify Service in real API
    let svc = client
        .get_service(COREDNS_NAMESPACE, COREDNS_SERVICE_NAME)
        .await
        .unwrap();
    assert_eq!(svc["spec"]["clusterIP"].as_str().unwrap(), "10.43.0.10");
    assert_eq!(
        svc["spec"]["selector"]["k8s-app"].as_str().unwrap(),
        "coredns"
    );

    // 6. Verify Deployment in real API
    let dep = client
        .get_deployment(COREDNS_NAMESPACE, COREDNS_DEPLOYMENT_NAME)
        .await
        .unwrap();
    assert_eq!(dep["spec"]["replicas"].as_i64().unwrap(), 1);
    assert_eq!(
        dep["spec"]["template"]["spec"]["nodeSelector"]["diorama.io/runtime"],
        "ordinary"
    );
    assert_eq!(
        dep["spec"]["template"]["spec"]["containers"][0]["image"]
            .as_str()
            .unwrap(),
        "docker.io/coredns/coredns:1.14.4"
    );
}

#[tokio::test]
async fn test_repeated_startup_preserves_unrelated_configmap_keys_and_metadata() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();
    let _ = client.create_namespace(COREDNS_NAMESPACE).await;

    let config = CoreDnsConfig::new().with_disable_ipv6(false);
    let reconciler = DnsReconciler::new(&config);

    // Cold start
    reconciler.reconcile(&client).await.unwrap();

    // Mutate existing ConfigMap with extra custom data key and custom metadata label
    client
        .patch_configmap(
            COREDNS_NAMESPACE,
            COREDNS_CONFIGMAP_NAME,
            json!({
                "metadata": {
                    "labels": {
                        "operator.custom/managed": "true"
                    }
                },
                "data": {
                    "Corefile": "old-corefile",
                    "custom.server": "external.domain:53 { errors }"
                }
            }),
        )
        .await
        .unwrap();

    // Repeat reconciliation
    let report = reconciler.reconcile(&client).await.unwrap();
    assert!(
        report.config_map_patched,
        "ConfigMap must be patched, not recreated"
    );
    assert!(
        !report.config_map_created,
        "ConfigMap must not be recreated"
    );

    // Fetch ConfigMap and verify Corefile was updated, while custom.server was preserved
    let updated_cm = client
        .get_configmap(COREDNS_NAMESPACE, COREDNS_CONFIGMAP_NAME)
        .await
        .unwrap();
    assert_eq!(
        updated_cm["metadata"]["labels"]["operator.custom/managed"], "true",
        "Unrelated metadata labels must be preserved"
    );
    let data = updated_cm["data"].as_object().unwrap();
    assert_eq!(
        data.get("custom.server")
            .and_then(serde_json::Value::as_str),
        Some("external.domain:53 { errors }"),
        "Unrelated data keys must be preserved"
    );
    let corefile = data
        .get("Corefile")
        .and_then(serde_json::Value::as_str)
        .unwrap();
    assert!(
        corefile.contains("in-addr.arpa ip6.arpa"),
        "Corefile must be updated to dual-stack configuration"
    );
}

#[tokio::test]
async fn test_service_recreation_on_cluster_ip_change() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();
    let _ = client.create_namespace(COREDNS_NAMESPACE).await;

    let config = CoreDnsConfig::new();
    let reconciler = DnsReconciler::new(&config);

    // Initial reconciliation
    reconciler.reconcile(&client).await.unwrap();

    // Modify Service to simulate drift/mismatched ClusterIP (clusterIP is immutable on update, so recreate)
    let mut svc = client
        .get_service(COREDNS_NAMESPACE, COREDNS_SERVICE_NAME)
        .await
        .unwrap();
    svc["spec"]["clusterIP"] = json!("10.43.0.99");
    if let Some(obj) = svc.get_mut("metadata").and_then(|m| m.as_object_mut()) {
        obj.remove("resourceVersion");
    }
    client
        .delete_service(COREDNS_NAMESPACE, COREDNS_SERVICE_NAME)
        .await
        .unwrap();
    client.create_service(COREDNS_NAMESPACE, svc).await.unwrap();

    // Repeat reconciliation must detect changed ClusterIP and recreate service
    let report = reconciler.reconcile(&client).await.unwrap();
    assert!(
        report.service_recreated,
        "Service must be recreated when ClusterIP changes"
    );

    let current_svc = client
        .get_service(COREDNS_NAMESPACE, COREDNS_SERVICE_NAME)
        .await
        .unwrap();
    assert_eq!(
        current_svc["spec"]["clusterIP"].as_str().unwrap(),
        "10.43.0.10",
        "ClusterIP must be restored to canonical 10.43.0.10"
    );
}

#[tokio::test]
async fn test_service_updated_without_recreation_when_cluster_ip_unchanged() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();
    let _ = client.create_namespace(COREDNS_NAMESPACE).await;

    let config = CoreDnsConfig::new();
    let reconciler = DnsReconciler::new(&config);

    // Initial reconciliation
    reconciler.reconcile(&client).await.unwrap();

    // Modify a mutable field and add custom label/annotation on the service without touching clusterIP
    let mut svc = client
        .get_service(COREDNS_NAMESPACE, COREDNS_SERVICE_NAME)
        .await
        .unwrap();
    svc["spec"]["sessionAffinity"] = json!("ClientIP");
    svc["metadata"]["labels"]["custom.service/label"] = json!("preserved-label");
    svc["metadata"]["annotations"] = json!({"custom.service/annotation": "preserved-annotation"});
    client
        .update_service(COREDNS_NAMESPACE, COREDNS_SERVICE_NAME, svc)
        .await
        .unwrap();

    // Repeat reconciliation must NOT recreate the service
    let report = reconciler.reconcile(&client).await.unwrap();
    assert!(
        !report.service_recreated,
        "Service must NOT be recreated when ClusterIP is identical"
    );
    assert!(
        report.service_updated,
        "Service mutable specification should be updated in-place"
    );

    let updated_svc = client
        .get_service(COREDNS_NAMESPACE, COREDNS_SERVICE_NAME)
        .await
        .unwrap();
    assert_eq!(
        updated_svc["metadata"]["labels"]["custom.service/label"], "preserved-label",
        "Custom service labels must be preserved on in-place update"
    );
    assert_eq!(
        updated_svc["metadata"]["annotations"]["custom.service/annotation"], "preserved-annotation",
        "Custom service annotations must be preserved on in-place update"
    );
    assert_eq!(
        updated_svc["metadata"]["labels"]["k8s-app"], "coredns",
        "Standard service labels must be present"
    );
}

#[tokio::test]
async fn test_readiness_timeout_and_healthy_reporting() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();
    let _ = client.create_namespace(COREDNS_NAMESPACE).await;

    let config = CoreDnsConfig::new().with_readiness_timeout(Duration::from_millis(150));
    let service = CoreDnsService::new(config, Arc::new(client.clone()));

    // Start service (reconciles manifests)
    service.start().await.unwrap();
    assert!(service.is_running());
    assert!(!service.is_ready());

    // Deployment has replicas=1 but status.readyReplicas=0, so readiness check should report not healthy
    let health_before = service.check_readiness().await.unwrap();
    assert!(!health_before.is_healthy);
    assert_eq!(health_before.ready_replicas, 0);

    // wait_for_readiness should time out and return DnsError::ReadinessTimeout
    let err = service
        .wait_for_readiness(Duration::from_millis(150))
        .await
        .unwrap_err();
    assert!(
        matches!(err, DnsError::ReadinessTimeout { .. }),
        "Expected ReadinessTimeout, got {err:?}"
    );
    assert_eq!(err.diagnostic_code(), "dns-readiness-timeout");
    assert!(
        !service.is_ready(),
        "Service must not be marked ready on timeout"
    );

    // Simulate pod becoming ready by updating Deployment status.readyReplicas = 1
    let mut dep = client
        .get_deployment(COREDNS_NAMESPACE, COREDNS_DEPLOYMENT_NAME)
        .await
        .unwrap();
    dep["status"] = json!({
        "replicas": 1,
        "readyReplicas": 1,
        "updatedReplicas": 1,
        "availableReplicas": 1
    });
    client
        .update_deployment(COREDNS_NAMESPACE, COREDNS_DEPLOYMENT_NAME, dep)
        .await
        .unwrap();

    // Now wait_for_readiness must succeed
    service
        .wait_for_readiness(Duration::from_secs(2))
        .await
        .unwrap();
    assert!(service.is_ready());

    let health_after = service.check_readiness().await.unwrap();
    assert!(health_after.is_healthy);
    assert_eq!(health_after.ready_replicas, 1);
}

#[tokio::test]
async fn test_supervisor_adapter_lifecycle_and_failure_policy() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();
    let _ = client.create_namespace(COREDNS_NAMESPACE).await;

    // Scenario 1: Failure without false ready (readiness timeout)
    {
        let config = CoreDnsConfig::new().with_readiness_timeout(Duration::from_millis(50));
        let service = CoreDnsService::new(config, Arc::new(client.clone()));
        let reg = CoreDnsAdapter::registration(
            diorama_dns::COMPONENT_COREDNS,
            service.clone(),
            vec![],
            Duration::from_millis(500),
        );

        let supervisor = Supervisor::new(vec![reg]).expect("supervisor creation");
        let (_stop_handle, stop_receiver) = stop_channel();
        let report = supervisor.run(stop_receiver).await;

        match &report.cause {
            StopCause::Fatal(failure) => {
                assert_eq!(failure.component, diorama_dns::COMPONENT_COREDNS);
                assert!(
                    matches!(
                        failure.kind,
                        diorama_supervisor::FailureKind::Adapter("dns-readiness-timeout")
                            | diorama_supervisor::FailureKind::StartupTimeout
                    ),
                    "Expected Adapter or StartupTimeout failure, got {:?}",
                    failure.kind
                );
            },
            other => panic!("Expected Fatal failure, got {other:?}"),
        }
        assert!(
            !service.is_ready(),
            "Service must never be marked ready on failure"
        );
    }

    // Scenario 2: Successful readiness and supervisor coordinated stop
    {
        let config = CoreDnsConfig::new().with_readiness_timeout(Duration::from_secs(2));
        let service = CoreDnsService::new(config, Arc::new(client.clone()));

        // Mark deployment ready beforehand
        let mut dep = client
            .get_deployment(COREDNS_NAMESPACE, COREDNS_DEPLOYMENT_NAME)
            .await
            .unwrap();
        dep["status"] = json!({
            "replicas": 1,
            "readyReplicas": 1
        });
        client
            .update_deployment(COREDNS_NAMESPACE, COREDNS_DEPLOYMENT_NAME, dep)
            .await
            .unwrap();

        let reg = CoreDnsAdapter::registration(
            diorama_dns::COMPONENT_COREDNS,
            service.clone(),
            vec![],
            Duration::from_secs(5),
        );

        let supervisor = Supervisor::new(vec![reg]).expect("supervisor creation");
        let (stop_handle, stop_receiver) = stop_channel();
        let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

        // Wait until service is running and ready
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while (!service.is_running() || !service.is_ready())
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(service.is_running(), "Service must be running");
        assert!(service.is_ready(), "Service must be ready");

        // Send graceful stop
        stop_handle.stop();
        let report = sup_handle.await.expect("supervisor task joins");
        assert!(matches!(report.cause, StopCause::Requested));
        assert!(!service.is_running(), "Service must be stopped");
    }
}

#[tokio::test]
async fn test_custom_offline_image_and_container_mode() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();
    let _ = client.create_namespace(COREDNS_NAMESPACE).await;

    let custom_image = "registry.local:5000/coredns:1.14.4-offline";
    let config = CoreDnsConfig::new()
        .with_container_mode(true)
        .with_image(custom_image);

    let reconciler = DnsReconciler::new(&config);
    reconciler.reconcile(&client).await.unwrap();

    let dep = client
        .get_deployment(COREDNS_NAMESPACE, COREDNS_DEPLOYMENT_NAME)
        .await
        .unwrap();
    let container = &dep["spec"]["template"]["spec"]["containers"][0];
    assert_eq!(
        container["image"].as_str().unwrap(),
        custom_image,
        "Offline custom image must be propagated to Deployment"
    );
    assert!(
        container["resources"].get("limits").is_none(),
        "Container mode must omit deployment memory limits"
    );

    let cm = client
        .get_configmap(COREDNS_NAMESPACE, COREDNS_CONFIGMAP_NAME)
        .await
        .unwrap();
    let corefile = cm["data"]["Corefile"].as_str().unwrap();
    assert!(
        corefile.contains("forward . 1.1.1.1 8.8.8.8"),
        "Container mode must use public forwarders by default"
    );
}
