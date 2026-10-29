use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

use diorama_apiserver::{
    ApiserverConfig, ApiserverService, KubernetesApiClient, KubernetesStorage,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_storage::{
    COMPONENT_LOCAL_PATH, DEFAULT_BASE_STORAGE_PATH, DEFAULT_PROVISIONER_IMAGE,
    LOCAL_PATH_CONFIGMAP_NAME, LOCAL_PATH_DEPLOYMENT_NAME, LOCAL_PATH_NAMESPACE,
    LOCAL_PATH_STORAGE_CLASS_NAME, LocalPathAdapter, LocalPathConfig, LocalPathReconciler,
    LocalPathService, StorageError,
};
use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, LifecycleObserver, LifecycleSnapshot, Registration, StopCause, Supervisor,
    stop_channel,
};
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

struct CoreWorker<F>(F);
impl<F, Fut> Adapter for CoreWorker<F>
where
    F: FnOnce(AdapterContext) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), AdapterError>> + Send + 'static,
{
    fn run(self: Box<Self>, context: AdapterContext) -> AdapterFuture {
        Box::pin((self.0)(context))
    }
}

async fn until(
    observer: &mut LifecycleObserver,
    predicate: impl Fn(&LifecycleSnapshot) -> bool,
) -> Arc<LifecycleSnapshot> {
    loop {
        let snapshot = observer.snapshot();
        if predicate(&snapshot) {
            return snapshot;
        }
        observer.changed().await.unwrap();
    }
}

#[tokio::test]
async fn local_path_does_not_advertise_unreported_csi_capacity() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();
    let config = LocalPathConfig::new();
    assert!(!config.csi_enabled);
    let reconciler = LocalPathReconciler::new(&config);
    let report = reconciler.reconcile(&client).await.unwrap();
    assert!(!report.csi_driver_created);
    let name = diorama_storage::LOCAL_PATH_PROVISIONER_NAME;
    let driver = diorama_storage::manifests::generate_csi_driver(name, false, true, true);
    client
        .create_cluster_object("storage.k8s.io", "CSIDriver", "csidrivers", driver.clone())
        .await
        .unwrap();
    // Upgrade removes only the old component-owned false capacity advertisement.
    reconciler.reconcile(&client).await.unwrap();
    assert!(matches!(
        client
            .get_cluster_object("storage.k8s.io", "csidrivers", name)
            .await,
        Err(diorama_apiserver::ApiserverError::NotFound { .. })
    ));
    let mut external = driver;
    external["metadata"]["labels"] = json!({"app":"operator-owned"});
    client
        .create_cluster_object("storage.k8s.io", "CSIDriver", "csidrivers", external)
        .await
        .unwrap();
    reconciler.reconcile(&client).await.unwrap();
    assert_eq!(
        client
            .get_cluster_object("storage.k8s.io", "csidrivers", name)
            .await
            .unwrap()["metadata"]["labels"]["app"],
        "operator-owned"
    );
}

#[tokio::test]
async fn test_cold_startup_reconciliation_real_api() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let config = LocalPathConfig::new();
    let reconciler = LocalPathReconciler::new(&config);

    // 1. Cold start reconciliation
    let report = reconciler.reconcile(&client).await.unwrap();
    assert!(report.namespace_created, "Namespace must be created");
    assert!(
        report.service_account_created,
        "ServiceAccount must be created"
    );
    assert!(report.cluster_role_created, "ClusterRole must be created");
    assert!(
        report.cluster_role_binding_created,
        "ClusterRoleBinding must be created"
    );
    assert!(report.role_created, "Role must be created");
    assert!(report.role_binding_created, "RoleBinding must be created");
    assert!(report.config_map_created, "ConfigMap must be created");
    assert!(report.storage_class_created, "StorageClass must be created");
    assert!(report.deployment_created, "Deployment must be created");

    // 2. Verify Namespace in real API
    let ns = client.get_namespace(LOCAL_PATH_NAMESPACE).await.unwrap();
    assert_eq!(
        ns["metadata"]["name"].as_str().unwrap(),
        LOCAL_PATH_NAMESPACE
    );

    // 3. Verify ConfigMap in real API
    let cm = client
        .get_configmap(LOCAL_PATH_NAMESPACE, LOCAL_PATH_CONFIGMAP_NAME)
        .await
        .unwrap();
    let config_json = cm["data"]["config.json"].as_str().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(config_json).unwrap();
    let paths = parsed["nodePathMap"][0]["paths"].as_array().unwrap();
    assert_eq!(paths[0].as_str().unwrap(), DEFAULT_BASE_STORAGE_PATH);

    // 4. Verify StorageClass in real API
    let sc = client
        .get_storage_class(LOCAL_PATH_STORAGE_CLASS_NAME)
        .await
        .unwrap();
    assert_eq!(
        sc["metadata"]["name"].as_str().unwrap(),
        LOCAL_PATH_STORAGE_CLASS_NAME
    );
    assert_eq!(sc["provisioner"].as_str().unwrap(), "rancher.io/local-path");
    assert_eq!(
        sc["metadata"]["annotations"]["storageclass.kubernetes.io/is-default-class"]
            .as_str()
            .unwrap(),
        "true"
    );

    // 5. Verify Deployment in real API
    let dep = client
        .get_deployment(LOCAL_PATH_NAMESPACE, LOCAL_PATH_DEPLOYMENT_NAME)
        .await
        .unwrap();
    assert_eq!(dep["spec"]["replicas"].as_i64().unwrap(), 1);
    assert_eq!(
        dep["spec"]["template"]["spec"]["nodeSelector"]["diorama.io/runtime"],
        "ordinary"
    );
    let container = &dep["spec"]["template"]["spec"]["containers"][0];
    assert_eq!(
        container["image"].as_str().unwrap(),
        DEFAULT_PROVISIONER_IMAGE
    );
}

#[tokio::test]
async fn test_repeat_startup_converges_idempotently_and_preserves_custom_config() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let config = LocalPathConfig::new();
    let reconciler = LocalPathReconciler::new(&config);

    // Cold start
    reconciler.reconcile(&client).await.unwrap();

    // Mutate existing ConfigMap with extra custom data key and custom metadata label
    client
        .patch_configmap(
            LOCAL_PATH_NAMESPACE,
            LOCAL_PATH_CONFIGMAP_NAME,
            json!({
                "metadata": {
                    "labels": {
                        "custom.company.io/managed": "true"
                    }
                },
                "data": {
                    "custom-storage-policy.yaml": "shared: false\nquota: unlimited\n"
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
    assert!(
        !report.storage_class_created,
        "StorageClass must not be recreated"
    );
    assert!(
        !report.deployment_created,
        "Deployment must not be recreated"
    );

    // Fetch ConfigMap and verify custom keys and labels preserved
    let updated_cm = client
        .get_configmap(LOCAL_PATH_NAMESPACE, LOCAL_PATH_CONFIGMAP_NAME)
        .await
        .unwrap();
    assert_eq!(
        updated_cm["metadata"]["labels"]["custom.company.io/managed"], "true",
        "Unrelated metadata labels must be preserved"
    );
    let data = updated_cm["data"].as_object().unwrap();
    assert_eq!(
        data.get("custom-storage-policy.yaml")
            .and_then(serde_json::Value::as_str),
        Some("shared: false\nquota: unlimited\n"),
        "Unrelated data keys must be preserved"
    );
    assert!(
        data.contains_key("config.json"),
        "Canonical config.json must be preserved/updated"
    );
}

#[tokio::test]
async fn test_disabled_mode_creates_no_components() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let config = LocalPathConfig::new().with_enabled(false);
    let reconciler = LocalPathReconciler::new(&config);

    // 1. Reconcile in disabled mode
    let report = reconciler.reconcile(&client).await.unwrap();
    assert!(!report.namespace_created);
    assert!(!report.storage_class_created);
    assert!(!report.deployment_created);
    assert!(!report.config_map_created);

    // 2. Ensure resources do NOT exist in the API
    assert!(
        client.get_namespace(LOCAL_PATH_NAMESPACE).await.is_err(),
        "Namespace should not exist in disabled mode"
    );
    assert!(
        client
            .get_storage_class(LOCAL_PATH_STORAGE_CLASS_NAME)
            .await
            .is_err(),
        "StorageClass should not exist in disabled mode"
    );

    // 3. Verify LocalPathAdapter immediately marks ready in disabled mode without starting deployment
    let service = LocalPathService::new(config, Arc::new(client.clone()));
    let reg = LocalPathAdapter::registration(
        COMPONENT_LOCAL_PATH,
        service.clone(),
        vec![],
        Duration::from_secs(5),
    );

    let (supervisor, mut observer) = Supervisor::new(vec![reg])
        .expect("supervisor creation")
        .with_observer();
    let (stop_handle, stop_receiver) = stop_channel();
    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    // Wait until adapter reaches ready
    let snap = until(&mut observer, |s| {
        s.components
            .iter()
            .all(|c| c.state == diorama_supervisor::ComponentState::Ready)
    })
    .await;
    assert!(!snap.degraded);

    // Send graceful stop
    stop_handle.stop();
    let sup_report = sup_handle.await.expect("supervisor task joins");
    assert!(matches!(sup_report.cause, StopCause::Requested));
    assert!(
        sup_report.failures.is_empty(),
        "Disabled mode must not produce failures"
    );
}

#[tokio::test]
async fn test_readiness_timeout_and_healthy_reporting() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let config = LocalPathConfig::new().with_readiness_timeout(Duration::from_millis(150));
    let service = LocalPathService::new(config, Arc::new(client.clone()));

    // Start service (reconciles manifests)
    service.start().await.unwrap();
    assert!(service.is_running());
    assert!(!service.is_ready());

    // Deployment has replicas=1 but status.readyReplicas=0, so readiness check should report not healthy
    let health_before = service.check_readiness().await.unwrap();
    assert!(!health_before.is_healthy);
    assert_eq!(health_before.ready_replicas, 0);

    // wait_for_readiness should time out and return StorageError::ReadinessTimeout
    let err = service
        .wait_for_readiness(Duration::from_millis(150))
        .await
        .unwrap_err();
    assert!(
        matches!(err, StorageError::ReadinessTimeout { .. }),
        "Expected ReadinessTimeout, got {err:?}"
    );
    assert_eq!(err.diagnostic_code(), "storage-readiness-timeout");
    assert!(
        !service.is_ready(),
        "Service must not be marked ready on timeout"
    );

    // Simulate pod becoming ready by updating Deployment status.readyReplicas = 1
    let mut dep = client
        .get_deployment(LOCAL_PATH_NAMESPACE, LOCAL_PATH_DEPLOYMENT_NAME)
        .await
        .unwrap();
    dep["status"] = json!({
        "replicas": 1,
        "readyReplicas": 1,
        "updatedReplicas": 1,
        "availableReplicas": 1
    });
    client
        .update_deployment(LOCAL_PATH_NAMESPACE, LOCAL_PATH_DEPLOYMENT_NAME, dep)
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
async fn test_injected_optional_deployment_failure_leaves_core_api_healthy() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let config = LocalPathConfig::new().with_readiness_timeout(Duration::from_millis(100));
    let service = LocalPathService::new(config, Arc::new(client.clone()));
    service.set_injected_failure(true);

    // Supervisor registration with FailurePolicy::Degrade
    let storage_reg = LocalPathAdapter::registration(
        COMPONENT_LOCAL_PATH,
        service.clone(),
        vec![],
        Duration::from_secs(5),
    );

    // Also register a core dummy service that stays running
    let core_spec = ComponentSpec {
        id: "core-controlplane".to_string(),
        prerequisites: vec![],
        kind: ComponentKind::LongRunning,
        failure_policy: FailurePolicy::Fatal,
        startup_timeout: Duration::from_secs(5),
    };
    let core_reg = Registration::new(
        core_spec,
        CoreWorker(|mut ctx: AdapterContext| async move {
            assert!(ctx.ready());
            while ctx.changed().await == diorama_supervisor::StopPhase::Running {}
            Ok(())
        }),
    );

    let (supervisor, mut observer) = Supervisor::new(vec![core_reg, storage_reg])
        .expect("supervisor creation")
        .with_observer();

    let (stop_handle, stop_receiver) = stop_channel();
    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    // Wait until diagnostics reflect degraded state
    let snap = until(&mut observer, |s| s.degraded).await;
    assert!(
        snap.degraded,
        "Supervisor diagnostics must report degraded == true"
    );

    let failure = snap
        .failures
        .iter()
        .find(|f| f.component == COMPONENT_LOCAL_PATH)
        .expect("storage failure must be recorded");
    assert_eq!(
        failure.kind,
        diorama_supervisor::FailureKind::Adapter("storage-injected-failure"),
        "Diagnostic failure code must reflect injected failure"
    );

    // Core API remains completely healthy, responsive and operational!
    let ns_create_result = client.create_namespace("post-degrade-namespace").await;
    assert!(
        ns_create_result.is_ok(),
        "Core apiserver must remain operational and create namespaces despite storage degradation"
    );
    let ns_list = client.list_namespaces().await.unwrap();
    let items = ns_list["items"].as_array().expect("items array");
    assert!(
        items
            .iter()
            .any(|item| item["metadata"]["name"].as_str() == Some("post-degrade-namespace"))
    );

    // Gracefully stop the supervisor
    stop_handle.stop();
    let report = sup_handle.await.expect("supervisor task joins");
    assert!(matches!(report.cause, StopCause::Requested));
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].component, COMPONENT_LOCAL_PATH);
}

#[tokio::test]
async fn test_custom_images_and_path_propagation() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let custom_provisioner = "registry.local:5000/rancher/local-path-provisioner:v0.0.31-custom";
    let custom_helper = "registry.local:5000/rancher/library-busybox:1.36.1-custom";
    let custom_path = "/var/mnt/k8s-local-storage";

    let config = LocalPathConfig::new()
        .with_provisioner_image(custom_provisioner)
        .with_helper_image(custom_helper)
        .with_storage_path(custom_path);

    let reconciler = LocalPathReconciler::new(&config);
    reconciler.reconcile(&client).await.unwrap();

    // Verify deployment container image
    let dep = client
        .get_deployment(LOCAL_PATH_NAMESPACE, LOCAL_PATH_DEPLOYMENT_NAME)
        .await
        .unwrap();
    assert_eq!(
        dep["spec"]["template"]["spec"]["containers"][0]["image"]
            .as_str()
            .unwrap(),
        custom_provisioner,
        "Custom provisioner image must be set in deployment"
    );

    // Verify ConfigMap config.json
    let cm = client
        .get_configmap(LOCAL_PATH_NAMESPACE, LOCAL_PATH_CONFIGMAP_NAME)
        .await
        .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(cm["data"]["config.json"].as_str().unwrap()).unwrap();
    assert_eq!(
        parsed["nodePathMap"][0]["paths"][0].as_str().unwrap(),
        custom_path,
        "Custom base path must be set in config.json"
    );

    let helper_pod_yaml = cm["data"]["helperPod.yaml"].as_str().unwrap();
    assert!(
        helper_pod_yaml.contains(custom_helper),
        "Custom helper image must be embedded into helperPod.yaml"
    );
}
