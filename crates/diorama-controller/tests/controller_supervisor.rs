use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use diorama_apiserver::supervisor::ApiserverAdapter;
use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_controller::{
    COMPONENT_CONTROLLER_MANAGER, ControllerError, ControllerManagerAdapter,
    ControllerManagerConfig, ControllerManagerService,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_supervisor::{StopCause, Supervisor, stop_channel};
use tempfile::TempDir;

fn setup_test_environment(dir: &TempDir) -> (ApiserverService, ControllerManagerConfig) {
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let datastore_dir = dir.path().join("datastore");

    // 1. Generate cluster PKI and credentials
    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "test-node".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    // 2. Open datastore engine and storage
    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir)).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    // 3. Create ApiserverService
    let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    let apiserver_service = ApiserverService::new(apiserver_config, storage);

    // 4. Create ControllerManagerConfig
    let controller_config = ControllerManagerConfig::default_for_pki(&pki_dir, node_ip);

    (apiserver_service, controller_config)
}

#[tokio::test]
async fn test_controller_manager_startup_and_authenticated_identity() {
    let temp = TempDir::new().unwrap();
    let (apiserver, controller_config) = setup_test_environment(&temp);

    // Start apiserver
    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    let apiserver_arc = Arc::new(apiserver);
    let controller_svc = ControllerManagerService::new(controller_config, apiserver_arc.clone());

    // 1. Check prerequisites
    controller_svc.check_prerequisites().await.unwrap();

    // 2. Verify authenticated identity
    let client = controller_svc.client();
    let created = client
        .create_namespace("controller-test-ns")
        .await
        .expect("system:kube-controller-manager client can create namespace");
    assert_eq!(created["metadata"]["name"], "controller-test-ns");

    let namespaces = client
        .list_namespaces()
        .await
        .expect("system:kube-controller-manager client can list namespaces");
    let items = namespaces
        .get("items")
        .and_then(|i| i.as_array())
        .expect("items array");
    assert!(
        !items.is_empty(),
        "expected controller-created namespace to be present"
    );

    // 3. Start service and verify readiness
    controller_svc.start().await.unwrap();
    assert!(controller_svc.is_running());

    let health = controller_svc.check_readiness().await.unwrap();
    assert!(health.is_healthy);
    assert!(health.authenticated);
    assert!(health.apiserver_connected);
    assert!(!health.configured_controllers.is_empty());
    assert_eq!(
        health.active_controllers,
        vec![
            "cronjob",
            "daemonset",
            "deployment",
            "endpoints",
            "endpointslice",
            "garbagecollector",
            "job",
            "replicaset",
            "statefulset",
        ]
    );

    // 4. Stop service
    controller_svc.stop();
    assert!(!controller_svc.is_running());

    let stopped_health = controller_svc.check_readiness().await.unwrap();
    assert!(!stopped_health.is_healthy);
}

#[tokio::test]
async fn test_controller_manager_supervision_lifecycle() {
    let temp = TempDir::new().unwrap();
    let (apiserver, controller_config) = setup_test_environment(&temp);

    let apiserver_arc = Arc::new(apiserver.clone());
    let controller_svc = ControllerManagerService::new(controller_config, apiserver_arc);

    let timeout = Duration::from_secs(10);

    let apiserver_reg = ApiserverAdapter::registration("apiserver", apiserver, Vec::new(), timeout);
    let controller_reg = ControllerManagerAdapter::registration(
        COMPONENT_CONTROLLER_MANAGER,
        controller_svc.clone(),
        vec!["apiserver".to_string()],
        timeout,
    );

    let supervisor =
        Supervisor::new(vec![apiserver_reg, controller_reg]).expect("supervisor creation succeeds");

    let (stop_handle, stop_receiver) = stop_channel();
    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    // Allow supervisor to start adapters and confirm readiness via bounded polling
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !controller_svc.is_running() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        controller_svc.is_running(),
        "Controller manager service must be active after startup"
    );

    // Verify controller manager is healthy under supervisor
    let report = controller_svc.check_readiness().await.unwrap();
    assert!(report.is_healthy);
    assert!(report.authenticated);
    assert!(!report.configured_controllers.is_empty());
    assert_eq!(
        report.active_controllers,
        vec![
            "cronjob",
            "daemonset",
            "deployment",
            "endpoints",
            "endpointslice",
            "garbagecollector",
            "job",
            "replicaset",
            "statefulset",
        ]
    );

    // Stop supervisor gracefully
    stop_handle.stop();
    let report = sup_handle.await.expect("supervisor task joins");
    assert!(matches!(report.cause, StopCause::Requested));

    assert!(
        !controller_svc.is_running(),
        "Controller manager service must be stopped after shutdown"
    );
}

#[tokio::test]
async fn test_controller_manager_prerequisite_failures() {
    let temp = TempDir::new().unwrap();
    let (apiserver, mut controller_config) = setup_test_environment(&temp);

    // Test 1: Missing kubeconfig
    controller_config.kubeconfig = temp.path().join("nonexistent.kubeconfig");
    let missing_kubeconfig_service =
        ControllerManagerService::new(controller_config.clone(), Arc::new(apiserver.clone()));
    let res = missing_kubeconfig_service.check_prerequisites().await;
    assert!(matches!(
        res,
        Err(ControllerError::MissingCredential { component, .. }) if component == "kubeconfig"
    ));

    // Test 2: Missing root CA file
    controller_config.kubeconfig = temp.path().join("pki/kube-controller-manager.kubeconfig");
    controller_config.root_ca_file = temp.path().join("nonexistent_ca.crt");
    let missing_ca_service =
        ControllerManagerService::new(controller_config.clone(), Arc::new(apiserver.clone()));
    let res = missing_ca_service.check_prerequisites().await;
    assert!(matches!(
        res,
        Err(ControllerError::MissingCredential { component, .. }) if component == "root-ca"
    ));

    // Test 3: Missing service account signing key
    controller_config.root_ca_file = temp.path().join("pki/ca.crt");
    controller_config.service_account_private_key_file = temp.path().join("nonexistent_sa.key");
    let missing_sa_key_service =
        ControllerManagerService::new(controller_config, Arc::new(apiserver));
    let res = missing_sa_key_service.check_prerequisites().await;
    assert!(matches!(
        res,
        Err(ControllerError::MissingCredential { component, .. }) if component == "service-account-key"
    ));
}

#[tokio::test]
async fn test_controller_manager_adapter_custom_interval() {
    let temp = TempDir::new().unwrap();
    let (apiserver, controller_config) = setup_test_environment(&temp);
    let controller_svc = ControllerManagerService::new(controller_config, Arc::new(apiserver));
    let adapter = ControllerManagerAdapter::new(controller_svc)
        .with_reconcile_interval(Duration::from_millis(250));
    assert_eq!(adapter.reconcile_interval(), Duration::from_millis(250));
}
