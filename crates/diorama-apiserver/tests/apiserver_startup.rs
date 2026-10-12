use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;
use tempfile::TempDir;

use diorama_apiserver::{
    ApiserverAdapter, ApiserverConfig, ApiserverService, COMPONENT_APISERVER, DEFAULT_SECURE_PORT,
    DEFAULT_SERVICE_CLUSTER_IP_RANGE, DEFAULT_SERVICE_NODE_PORT_RANGE, KubernetesStorage,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_supervisor::{StopCause, Supervisor};

fn setup_fixture_pki(dir: &TempDir, node_ip: IpAddr) -> ApiserverConfig {
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let config = ClusterPkiConfig::new(pki_dir.clone(), "test-node".to_string(), node_ip);
    let pki = ClusterPki::new(config);
    pki.reconcile().expect("PKI reconcile succeeds");

    ApiserverConfig::default_for_pki(&pki_dir, node_ip)
}

fn setup_fixture_datastore(dir: &TempDir) -> (DatastoreEngine, KubernetesStorage) {
    let data_dir = dir.path().join("datastore");
    let ds_config = DatastoreConfig::new(data_dir);
    let (engine, _) = DatastoreEngine::open(ds_config).expect("datastore open succeeds");
    let client = engine.client();
    let storage = KubernetesStorage::new(client, "/registry");
    (engine, storage)
}

#[test]
fn baseline_configuration_flags_match_kubernetes_v1_35_7_specification() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let mut config = setup_fixture_pki(&temp, node_ip);
    config
        .feature_gates
        .insert("SizeBasedListCostEstimate".to_string(), false);

    let args = config.to_command_args();

    // Verify baseline Kubernetes v1.35.7 CLI arguments
    assert!(args.contains(&"--bind-address=127.0.0.1".to_string()));
    assert!(args.contains(&format!("--advertise-address={node_ip}")));
    assert!(args.contains(&format!("--secure-port={DEFAULT_SECURE_PORT}")));
    assert!(args.contains(&format!(
        "--service-cluster-ip-range={DEFAULT_SERVICE_CLUSTER_IP_RANGE}"
    )));
    assert!(args.contains(&format!(
        "--service-node-port-range={DEFAULT_SERVICE_NODE_PORT_RANGE}"
    )));
    assert!(args.contains(&"--authorization-mode=Node,RBAC".to_string()));
    assert!(args.contains(&"--anonymous-auth=false".to_string()));
    assert!(args.contains(&"--allow-privileged=true".to_string()));
    assert!(args.contains(&"--etcd-servers=http://127.0.0.1:2379".to_string()));
    assert!(args.contains(&"--etcd-prefix=/registry".to_string()));
    assert!(args.contains(&"--service-account-issuer=https://kubernetes.default.svc".to_string()));
    assert!(args.contains(&"--feature-gates=SizeBasedListCostEstimate=false".to_string()));

    // Verify Deviation D09: absence of obsolete edge memory overrides
    assert!(!args.iter().any(|a| a.contains("max-requests-inflight=100")));
    assert!(!args.iter().any(|a| a.contains("target-ram-mb")));
}

#[tokio::test]
async fn apiserver_supervised_startup_and_graceful_shutdown() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.10".parse().unwrap();
    let config = setup_fixture_pki(&temp, node_ip);
    let (_engine, storage) = setup_fixture_datastore(&temp);

    let service = ApiserverService::new(config, storage);
    let registration = ApiserverAdapter::registration(
        COMPONENT_APISERVER,
        service.clone(),
        Vec::new(),
        Duration::from_secs(10),
    );

    let supervisor = Supervisor::new(vec![registration]).expect("supervisor creation succeeds");

    let (stop_handle, stop_receiver) = diorama_supervisor::stop_channel();

    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    // Allow supervisor to start adapter and confirm readiness via bounded polling
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !service.is_running() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        service.is_running(),
        "Apiserver service must be active after startup"
    );

    // Stop supervisor gracefully
    stop_handle.stop();
    let report = sup_handle.await.expect("supervisor task joins");
    assert!(matches!(report.cause, StopCause::Requested));
    assert!(
        !service.is_running(),
        "Apiserver service must be stopped after shutdown"
    );
}

#[tokio::test]
async fn plain_restart_retains_persistent_state_and_client_access() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.20".parse().unwrap();
    let config = setup_fixture_pki(&temp, node_ip);
    let ds_data_dir = temp.path().join("datastore");

    // === Session 1: Initial startup & state creation ===
    {
        let ds_config = DatastoreConfig::new(ds_data_dir.clone());
        let (engine, _) = DatastoreEngine::open(ds_config).expect("datastore 1 open");
        let storage = KubernetesStorage::new(engine.client(), "/registry");
        let service = ApiserverService::new(config.clone(), storage);

        service.start().expect("service start succeeds");
        let client = service.admin_client();

        // Create Namespace
        let ns = client
            .create_namespace("production")
            .await
            .expect("create namespace succeeds");
        assert_eq!(ns["metadata"]["name"], "production");

        // Create ConfigMap
        let mut cm_data = BTreeMap::new();
        cm_data.insert("database_url".to_string(), "etcd://127.0.0.1".to_string());
        cm_data.insert("environment".to_string(), "prod".to_string());
        let cm = client
            .create_configmap("production", "app-settings", cm_data)
            .await
            .expect("create configmap succeeds");
        assert_eq!(cm["metadata"]["name"], "app-settings");
        assert_eq!(cm["data"]["environment"], "prod");

        service.stop();
    }

    // === Session 2: Plain restart on identical datastore directory ===
    {
        let ds_config = DatastoreConfig::new(ds_data_dir);
        let (engine, _) = DatastoreEngine::open(ds_config).expect("datastore 2 open");
        let storage = KubernetesStorage::new(engine.client(), "/registry");
        let service = ApiserverService::new(config, storage);

        service
            .check_prerequisites()
            .await
            .expect("prerequisites valid after restart");
        service.start().expect("service restart succeeds");
        let client = service.admin_client();

        // Client access is immediately preserved
        let ns = client
            .get_namespace("production")
            .await
            .expect("read namespace after restart succeeds");
        assert_eq!(ns["metadata"]["name"], "production");

        let cm = client
            .get_configmap("production", "app-settings")
            .await
            .expect("read configmap after restart succeeds");
        assert_eq!(cm["metadata"]["name"], "app-settings");
        assert_eq!(cm["data"]["database_url"], "etcd://127.0.0.1");
        assert_eq!(cm["data"]["environment"], "prod");

        service.stop();
    }
}

#[tokio::test]
async fn default_namespaces_bootstrapped_on_startup() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.30".parse().unwrap();
    let config = setup_fixture_pki(&temp, node_ip);
    let (_engine, storage) = setup_fixture_datastore(&temp);

    let service = ApiserverService::new(config, storage);
    service.check_prerequisites().await.unwrap();
    service.start().unwrap();
    let client = service.admin_client();

    for ns_name in &["default", "kube-system", "kube-node-lease"] {
        let ns = client
            .get_namespace(ns_name)
            .await
            .unwrap_or_else(|e| panic!("expected namespace {ns_name} to exist: {e:?}"));
        assert_eq!(ns["metadata"]["name"], *ns_name);
        assert_eq!(ns["status"]["phase"], "Active");
    }

    service.stop();
}
