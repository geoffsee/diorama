use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

use diorama_apiserver::{
    ApiserverConfig, ApiserverService, KubernetesApiClient, KubernetesStorage,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_platform::Architecture;
use diorama_portainer::config::{
    DEFAULT_EDGE_INSECURE_POLL, PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME,
    PORTAINER_AGENT_CONFIGMAP_NAME, PORTAINER_AGENT_DEPLOYMENT_NAME, PORTAINER_AGENT_PORT_EDGE,
    PORTAINER_AGENT_PORT_HTTP, PORTAINER_AGENT_SECRET_NAME, PORTAINER_AGENT_SERVICE_ACCOUNT_NAME,
    PORTAINER_AGENT_SERVICE_NAME, PORTAINER_NAMESPACE, PortainerAgentConfig,
};
use diorama_portainer::reconciler::PortainerReconciler;
use diorama_portainer::service::PortainerService;
use diorama_portainer::supervisor::{COMPONENT_PORTAINER, PortainerAdapter};
use diorama_supervisor::{
    LifecycleObserver, LifecycleSnapshot, StopCause, Supervisor, stop_channel,
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

fn sample_config() -> PortainerAgentConfig {
    PortainerAgentConfig::new("edge-fixture-id", "edge-fixture-key", Architecture::Amd64)
        .with_edge_secret(Some("edge-fixture-secret".to_string()))
        .with_edge_async(false)
        .with_edge_insecure_poll(DEFAULT_EDGE_INSECURE_POLL)
        .with_image("portainer/agent:test")
        .with_readiness_timeout(Duration::from_millis(50))
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
async fn test_cold_startup_reconciliation_real_api() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let config = sample_config();
    let reconciler = PortainerReconciler::new(&config);

    // 1. Cold start reconciliation
    let report = reconciler.reconcile(&client).await.unwrap();
    assert!(report.namespace_created, "Namespace must be created");
    assert!(
        report.service_account_created,
        "ServiceAccount must be created"
    );
    assert!(
        report.cluster_role_binding_created,
        "ClusterRoleBinding must be created"
    );
    assert!(report.config_map_created, "ConfigMap must be created");
    assert!(report.secret_created, "Secret must be created");
    assert!(report.service_created, "Service must be created");
    assert!(report.deployment_created, "Deployment must be created");
    assert_eq!(report.total_created(), 7);
    assert_eq!(report.total_preserved(), 0);
    assert!(report.all_retained());

    // 2. Verify Namespace in real API
    let ns = client.get_namespace(PORTAINER_NAMESPACE).await.unwrap();
    assert_eq!(ns["metadata"]["name"], PORTAINER_NAMESPACE);

    // 3. Verify ServiceAccount in real API
    let sa = client
        .get_service_account(PORTAINER_NAMESPACE, PORTAINER_AGENT_SERVICE_ACCOUNT_NAME)
        .await
        .unwrap();
    assert_eq!(sa["metadata"]["name"], PORTAINER_AGENT_SERVICE_ACCOUNT_NAME);
    assert_eq!(sa["metadata"]["namespace"], PORTAINER_NAMESPACE);

    // 4. Verify ClusterRoleBinding in real API
    let crb = client
        .get_cluster_role_binding(PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME)
        .await
        .unwrap();
    assert_eq!(crb.name, PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME);
    assert_eq!(crb.role_ref, "cluster-admin");

    // 5. Verify ConfigMap in real API
    let cm = client
        .get_configmap(PORTAINER_NAMESPACE, PORTAINER_AGENT_CONFIGMAP_NAME)
        .await
        .unwrap();
    assert_eq!(cm["data"]["EDGE_ID"], "edge-fixture-id");
    assert_eq!(cm["data"]["EDGE_ASYNC"], "false");
    assert_eq!(cm["data"]["EDGE_INSECURE_POLL"], "0");
    assert_eq!(cm["data"]["EDGE_SECRET"], "edge-fixture-secret");

    // 6. Verify Secret in real API
    let secret = client
        .get_secret(PORTAINER_NAMESPACE, PORTAINER_AGENT_SECRET_NAME)
        .await
        .unwrap();
    let secret_val = secret
        .get("stringData")
        .or_else(|| secret.get("data"))
        .unwrap();
    assert_eq!(secret_val["edge.key"], "ZWRnZS1maXh0dXJlLWtleQ==");
    assert!(secret.get("stringData").is_none());

    // 7. Verify Service in real API
    let svc = client
        .get_service(PORTAINER_NAMESPACE, PORTAINER_AGENT_SERVICE_NAME)
        .await
        .unwrap();
    assert_eq!(svc["spec"]["clusterIP"], "None");
    assert_eq!(svc["spec"]["publishNotReadyAddresses"], true);
    assert_eq!(
        svc["spec"]["selector"]["app"],
        PORTAINER_AGENT_DEPLOYMENT_NAME
    );
    let ports = svc["spec"]["ports"].as_array().unwrap();
    assert_eq!(ports.len(), 2);
    assert_eq!(ports[0]["port"], PORTAINER_AGENT_PORT_EDGE);
    assert_eq!(ports[1]["port"], PORTAINER_AGENT_PORT_HTTP);

    // 8. Verify Deployment in real API
    let dep = client
        .get_deployment(PORTAINER_NAMESPACE, PORTAINER_AGENT_DEPLOYMENT_NAME)
        .await
        .unwrap();
    assert_eq!(dep["spec"]["replicas"], 1);
    let container = &dep["spec"]["template"]["spec"]["containers"][0];
    assert_eq!(container["image"], "portainer/agent:test");
    assert_eq!(
        dep["spec"]["template"]["spec"]["serviceAccountName"],
        PORTAINER_AGENT_SERVICE_ACCOUNT_NAME
    );
}

async fn mutate_portainer_resources(client: &KubernetesApiClient) {
    client
        .patch_configmap(
            PORTAINER_NAMESPACE,
            PORTAINER_AGENT_CONFIGMAP_NAME,
            json!({
                "metadata": {
                    "annotations": {
                        "custom.company.io/managed": "true"
                    }
                },
                "data": {
                    "EDGE_ID": "user-modified-id",
                    "CUSTOM_USER_PARAM": "custom-val"
                }
            }),
        )
        .await
        .unwrap();

    client
        .update_deployment(
            PORTAINER_NAMESPACE,
            PORTAINER_AGENT_DEPLOYMENT_NAME,
            json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": PORTAINER_AGENT_DEPLOYMENT_NAME,
                    "namespace": PORTAINER_NAMESPACE,
                    "annotations": {
                        "ops.company.io/scaled-by": "admin"
                    }
                },
                "spec": {
                    "replicas": 3,
                    "selector": {
                        "matchLabels": { "app": PORTAINER_AGENT_DEPLOYMENT_NAME }
                    },
                    "template": {
                        "metadata": { "labels": { "app": PORTAINER_AGENT_DEPLOYMENT_NAME } },
                        "spec": {
                            "serviceAccountName": PORTAINER_AGENT_SERVICE_ACCOUNT_NAME,
                            "containers": [{
                                "name": "portainer-agent",
                                "image": "portainer/agent:custom-version"
                            }]
                        }
                    }
                }
            }),
        )
        .await
        .unwrap();
}

async fn verify_mutated_portainer_resources_preserved(client: &KubernetesApiClient) {
    let cm = client
        .get_configmap(PORTAINER_NAMESPACE, PORTAINER_AGENT_CONFIGMAP_NAME)
        .await
        .unwrap();
    assert_eq!(
        cm["data"]["EDGE_ID"], "user-modified-id",
        "EDGE_ID must retain user modification"
    );
    assert_eq!(
        cm["data"]["CUSTOM_USER_PARAM"], "custom-val",
        "Custom config keys must be retained"
    );
    assert_eq!(
        cm["metadata"]["annotations"]["custom.company.io/managed"], "true",
        "Custom annotations must be retained"
    );

    let dep = client
        .get_deployment(PORTAINER_NAMESPACE, PORTAINER_AGENT_DEPLOYMENT_NAME)
        .await
        .unwrap();
    assert_eq!(
        dep["spec"]["replicas"], 3,
        "Replicas must retain user scaling"
    );
    assert_eq!(
        dep["spec"]["template"]["spec"]["containers"][0]["image"], "portainer/agent:custom-version",
        "Image must retain user custom version"
    );
    assert_eq!(
        dep["metadata"]["annotations"]["ops.company.io/scaled-by"], "admin",
        "Deployment annotations must be retained"
    );

    let secret = client
        .get_secret(PORTAINER_NAMESPACE, PORTAINER_AGENT_SECRET_NAME)
        .await
        .unwrap();
    let secret_val = secret
        .get("stringData")
        .or_else(|| secret.get("data"))
        .unwrap();
    assert_eq!(secret_val["edge.key"], "ZWRnZS1maXh0dXJlLWtleQ==");
    assert!(secret.get("stringData").is_none());
}

#[tokio::test]
async fn test_repeat_startup_preserves_all_existing_objects_unchanged() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let config = sample_config();
    let reconciler = PortainerReconciler::new(&config);

    // 1. Initial cold startup
    let initial_report = reconciler.reconcile(&client).await.unwrap();
    assert_eq!(initial_report.total_created(), 7);

    // 2. Mutate existing objects with custom fields, annotations, labels, and specs
    mutate_portainer_resources(&client).await;

    // 3. Repeat startup reconciliation
    let repeat_report = reconciler.reconcile(&client).await.unwrap();
    assert_eq!(
        repeat_report.total_created(),
        0,
        "No resources should be created on repeated startup"
    );
    assert_eq!(
        repeat_report.total_preserved(),
        7,
        "All 7 resources must be preserved on repeated startup"
    );
    assert!(repeat_report.namespace_preserved);
    assert!(repeat_report.service_account_preserved);
    assert!(repeat_report.cluster_role_binding_preserved);
    assert!(repeat_report.config_map_preserved);
    assert!(repeat_report.secret_preserved);
    assert!(repeat_report.service_preserved);
    assert!(repeat_report.deployment_preserved);

    // 4. Verify existing resources retained all mutations
    verify_mutated_portainer_resources_preserved(&client).await;
}

#[tokio::test]
async fn test_missing_bootstrap_objects_created_consistently() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    // Create namespace and custom ConfigMap ahead of time
    client.create_namespace(PORTAINER_NAMESPACE).await.unwrap();
    let mut custom_data = BTreeMap::new();
    custom_data.insert("EDGE_ID".to_string(), "pre-existing-id".to_string());
    custom_data.insert("EDGE_ASYNC".to_string(), "true".to_string());
    custom_data.insert("CUSTOM_PARAM".to_string(), "pre-existing".to_string());
    client
        .create_configmap(
            PORTAINER_NAMESPACE,
            PORTAINER_AGENT_CONFIGMAP_NAME,
            custom_data,
        )
        .await
        .unwrap();

    // Reconcile with bootstrap configuration
    let config = sample_config();
    let reconciler = PortainerReconciler::new(&config);
    let report = reconciler.reconcile(&client).await.unwrap();

    // Namespace and ConfigMap existed, so preserved; others were missing, so created
    assert!(report.namespace_preserved, "Namespace was pre-existing");
    assert!(report.config_map_preserved, "ConfigMap was pre-existing");
    assert!(report.service_account_created, "ServiceAccount was missing");
    assert!(
        report.cluster_role_binding_created,
        "ClusterRoleBinding was missing"
    );
    assert!(report.secret_created, "Secret was missing");
    assert!(report.service_created, "Service was missing");
    assert!(report.deployment_created, "Deployment was missing");
    assert_eq!(report.total_created(), 5);
    assert_eq!(report.total_preserved(), 2);

    // Verify ConfigMap retained pre-existing values
    let cm = client
        .get_configmap(PORTAINER_NAMESPACE, PORTAINER_AGENT_CONFIGMAP_NAME)
        .await
        .unwrap();
    assert_eq!(cm["data"]["EDGE_ID"], "pre-existing-id");
    assert_eq!(cm["data"]["CUSTOM_PARAM"], "pre-existing");

    // Verify missing objects were created
    let dep = client
        .get_deployment(PORTAINER_NAMESPACE, PORTAINER_AGENT_DEPLOYMENT_NAME)
        .await
        .unwrap();
    assert_eq!(dep["spec"]["replicas"], 1);
}

#[tokio::test]
async fn test_supervisor_portainer_adapter_enabled_and_shutdown() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    // Set zero readiness timeout so the test passes immediately without pod runner
    let config = sample_config().with_readiness_timeout(Duration::ZERO);
    let service = PortainerService::new(config, Arc::new(client.clone()));
    let timeout = Duration::from_secs(5);

    let reg = PortainerAdapter::registration(COMPONENT_PORTAINER, service, vec![], timeout);

    let (supervisor, mut observer) = Supervisor::new(vec![reg]).unwrap().with_observer();
    let (stop_handle, stop_receiver) = stop_channel();

    let sup_task = tokio::spawn(supervisor.run(stop_receiver));

    // Wait until Portainer adapter reaches ready
    let snap = until(&mut observer, |s| {
        s.components
            .iter()
            .find(|c| c.component == COMPONENT_PORTAINER)
            .is_some_and(|c| c.state == diorama_supervisor::ComponentState::Ready)
    })
    .await;
    let comp = snap
        .components
        .iter()
        .find(|c| c.component == COMPONENT_PORTAINER)
        .unwrap();
    assert_eq!(comp.state, diorama_supervisor::ComponentState::Ready);

    // Check that all 7 objects were created
    assert!(client.get_namespace(PORTAINER_NAMESPACE).await.is_ok());
    assert!(
        client
            .get_deployment(PORTAINER_NAMESPACE, PORTAINER_AGENT_DEPLOYMENT_NAME)
            .await
            .is_ok()
    );

    // Stop supervisor
    stop_handle.stop();
    let report = sup_task.await.unwrap();
    assert_eq!(report.cause, StopCause::Requested);
}

#[tokio::test]
async fn readiness_timeout_bounds_a_long_poll_interval() {
    let temp = TempDir::new().unwrap();
    let (_apiserver, client) = setup_test_cluster(&temp);
    let config = sample_config();
    let reconciler = PortainerReconciler::new(&config);
    let started = std::time::Instant::now();
    let result = reconciler
        .wait_for_readiness(&client, Duration::from_millis(20), Duration::from_secs(10))
        .await;
    assert!(matches!(
        result,
        Err(diorama_portainer::error::PortainerError::ReadinessTimeout { .. })
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn stop_during_readiness_does_not_wait_for_timeout() {
    let temp = TempDir::new().unwrap();
    let (_apiserver, client) = setup_test_cluster(&temp);
    let service = PortainerService::new(
        sample_config().with_readiness_timeout(Duration::from_secs(30)),
        Arc::new(client.clone()),
    );
    let reg = PortainerAdapter::registration(
        COMPONENT_PORTAINER,
        service,
        vec![],
        Duration::from_mins(1),
    );
    let supervisor = Supervisor::new(vec![reg]).unwrap();
    let (stop, receiver) = stop_channel();
    let task = tokio::spawn(supervisor.run(receiver));
    tokio::time::timeout(Duration::from_secs(5), async {
        while client
            .get_deployment(PORTAINER_NAMESPACE, PORTAINER_AGENT_DEPLOYMENT_NAME)
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    stop.stop();
    let report = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.cause, StopCause::Requested);
}

#[tokio::test]
async fn test_supervisor_portainer_adapter_disabled_mode() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    // Disabled config (empty edge_id and edge_key)
    let disabled_config = PortainerAgentConfig::new("", "", Architecture::Amd64);
    assert!(!disabled_config.is_enabled());

    let service = PortainerService::new(disabled_config, Arc::new(client.clone()));
    let timeout = Duration::from_secs(5);

    let reg = PortainerAdapter::registration(COMPONENT_PORTAINER, service, vec![], timeout);

    let (supervisor, mut observer) = Supervisor::new(vec![reg]).unwrap().with_observer();
    let (stop_handle, stop_receiver) = stop_channel();

    let sup_task = tokio::spawn(supervisor.run(stop_receiver));

    // Disabled mode should immediately become ready without deploying any components
    until(&mut observer, |s| {
        s.components
            .iter()
            .find(|c| c.component == COMPONENT_PORTAINER)
            .is_some_and(|c| c.state == diorama_supervisor::ComponentState::Ready)
    })
    .await;

    // Verify namespace was NOT created
    assert!(client.get_namespace(PORTAINER_NAMESPACE).await.is_err());

    stop_handle.stop();
    let report = sup_task.await.unwrap();
    assert_eq!(report.cause, StopCause::Requested);
}

#[tokio::test]
async fn job_owned_deployment_suppresses_missing_legacy_bootstrap_resources() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();
    client.create_namespace(PORTAINER_NAMESPACE).await.unwrap();
    client.create_deployment(PORTAINER_NAMESPACE, json!({
        "apiVersion":"apps/v1","kind":"Deployment",
        "metadata":{"name":PORTAINER_AGENT_DEPLOYMENT_NAME,"labels":{"diorama.io/managed-by":"addon-job","diorama.io/addon":"portainer-agent"}},
        "spec":{"replicas":1,"selector":{"matchLabels":{"app":"portainer-agent"}},
        "template":{"metadata":{"labels":{"app":"portainer-agent"}},"spec":{"containers":[{"name":"agent","image":"ghcr.io/geoffsee/diorama-addon-portainer-agent:v1"}]}}}
    })).await.unwrap();
    let before = client
        .get_deployment(PORTAINER_NAMESPACE, PORTAINER_AGENT_DEPLOYMENT_NAME)
        .await
        .unwrap();
    let report = PortainerReconciler::new(&sample_config())
        .reconcile(&client)
        .await
        .unwrap();
    assert_eq!(report.total_created(), 0);
    assert!(
        client
            .get_secret(PORTAINER_NAMESPACE, PORTAINER_AGENT_SECRET_NAME)
            .await
            .is_err()
    );
    assert_eq!(
        before,
        client
            .get_deployment(PORTAINER_NAMESPACE, PORTAINER_AGENT_DEPLOYMENT_NAME)
            .await
            .unwrap()
    );
}
