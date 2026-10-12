use std::net::IpAddr;
use std::sync::Arc;
use tempfile::TempDir;

use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use dioramalet::{KubeletConfigOptions, KubeletError, KubeletService, MockRuntimeProvider, cri};

fn setup_test_environment(dir: &TempDir) -> (ApiserverService, KubeletConfigOptions) {
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let datastore_dir = dir.path().join("datastore");
    let kubelet_dir = dir.path().join("kubelet");
    std::fs::create_dir_all(&kubelet_dir).unwrap();

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

    // 4. Create KubeletConfigOptions
    let kubelet_options =
        KubeletConfigOptions::default_for_pki(&pki_dir, "test-node", "192.0.2.1", &kubelet_dir);

    (apiserver_service, kubelet_options)
}

#[tokio::test]
async fn test_node_registration_and_readiness() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    let apiserver_arc = Arc::new(apiserver);
    let runtime = Arc::new(MockRuntimeProvider::new("containerd"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime);

    // 1. Check prerequisites
    kubelet.check_prerequisites().await.unwrap();

    // 2. Start Kubelet service
    kubelet.start().await.unwrap();
    assert!(kubelet.is_running());

    // 3. Check health and readiness
    let health = kubelet.check_readiness().await.unwrap();
    assert!(health.is_healthy);
    assert!(health.node_ready);
    assert_eq!(health.node_name, "test-node");
    assert_eq!(health.runtime_provider, "containerd");

    // 4. Verify Node resource in API server
    let client = kubelet.client();
    let node = client.get_node("test-node").await.expect("Node exists");
    assert_eq!(node["metadata"]["name"], "test-node");

    let conditions = node["status"]["conditions"].as_array().expect("conditions");
    let ready_cond = conditions
        .iter()
        .find(|c| c["type"] == "Ready")
        .expect("Ready condition");
    assert_eq!(ready_cond["status"], "True");
    assert_eq!(ready_cond["reason"], "KubeletReady");

    let disk_cond = conditions
        .iter()
        .find(|c| c["type"] == "DiskPressure")
        .expect("DiskPressure condition");
    assert_eq!(disk_cond["status"], "False");

    let addresses = node["status"]["addresses"].as_array().expect("addresses");
    let ip_addr = addresses
        .iter()
        .find(|a| a["type"] == "InternalIP")
        .expect("InternalIP");
    assert_eq!(ip_addr["address"], "192.0.2.1");

    let hostname = addresses
        .iter()
        .find(|a| a["type"] == "Hostname")
        .expect("Hostname");
    assert_eq!(hostname["address"], "test-node");

    // 5. Verify Lease heartbeat in kube-node-lease
    let lease = client
        .get_lease("kube-node-lease", "test-node")
        .await
        .expect("Lease exists");
    assert_eq!(lease["metadata"]["name"], "test-node");
    assert_eq!(lease["spec"]["holderIdentity"], "test-node");
    assert_eq!(lease["spec"]["leaseDurationSeconds"], 40);

    // 6. Stop service
    kubelet.stop();
    assert!(!kubelet.is_running());
    let stopped_health = kubelet.check_readiness().await.unwrap();
    assert!(!stopped_health.is_healthy);
}

#[tokio::test]
async fn test_prerequisite_failures_identify_responsible_component() {
    let temp = TempDir::new().unwrap();
    let (apiserver, mut kubelet_options) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    // Negative 1: Missing kubeconfig
    let real_kubeconfig = kubelet_options.kubeconfig.clone();
    kubelet_options.kubeconfig = temp.path().join("missing.kubeconfig");
    let runtime = Arc::new(MockRuntimeProvider::new("containerd"));
    let kubelet_missing_kc = KubeletService::new(
        kubelet_options.clone(),
        apiserver_arc.clone(),
        runtime.clone(),
    );
    let err = kubelet_missing_kc.check_prerequisites().await.unwrap_err();
    assert_eq!(err.diagnostic_code(), "kubelet-credential-missing");

    // Restore kubeconfig
    kubelet_options.kubeconfig = real_kubeconfig;

    // Negative 2: Missing CA cert
    let real_ca = kubelet_options.ca_file.clone();
    kubelet_options.ca_file = temp.path().join("missing.crt");
    let kubelet_missing_ca = KubeletService::new(
        kubelet_options.clone(),
        apiserver_arc.clone(),
        runtime.clone(),
    );
    let err = kubelet_missing_ca.check_prerequisites().await.unwrap_err();
    assert_eq!(err.diagnostic_code(), "kubelet-credential-missing");

    // Restore CA
    kubelet_options.ca_file = real_ca;

    // Negative 3: Kubeconfig with invalid identity (wrong user)
    let bad_kubeconfig_path = temp.path().join("bad.kubeconfig");
    std::fs::write(
        &bad_kubeconfig_path,
        "apiVersion: v1\nusers:\n- name: hacker\n",
    )
    .unwrap();
    kubelet_options.kubeconfig = bad_kubeconfig_path;
    let kubelet_bad_id = KubeletService::new(
        kubelet_options.clone(),
        apiserver_arc.clone(),
        runtime.clone(),
    );
    let err = kubelet_bad_id.check_prerequisites().await.unwrap_err();
    assert_eq!(err.diagnostic_code(), "kubelet-auth-failed");

    // Negative 4: Missing runtime socket for non-mock CRI runtime
    kubelet_options.kubeconfig = temp.path().join("pki").join("kubelet.kubeconfig");
    kubelet_options.runtime_endpoint = "unix:///nonexistent/cri.sock".to_string();
    let kubelet_bad_socket = KubeletService::new(
        kubelet_options.clone(),
        apiserver_arc.clone(),
        Arc::new(RealCriMock),
    );
    let err = kubelet_bad_socket.check_prerequisites().await.unwrap_err();
    assert_eq!(err.diagnostic_code(), "kubelet-runtime-unavailable");
}

#[derive(Debug)]
struct RealCriMock;

/// A socket-backed provider shape: only `check_prerequisites` reaches it in this test,
/// so every CRI call answers with an empty or trivial result.
#[async_trait::async_trait]
impl dioramalet::RuntimeProvider for RealCriMock {
    fn provider_name(&self) -> &'static str {
        "containerd"
    }
    fn requires_socket(&self) -> bool {
        true
    }
    async fn run_pod_sandbox(&self, _c: &cri::PodSandboxConfig) -> Result<String, KubeletError> {
        Ok("sandbox".to_string())
    }
    async fn stop_pod_sandbox(&self, _id: &str) -> Result<(), KubeletError> {
        Ok(())
    }
    async fn remove_pod_sandbox(&self, _id: &str) -> Result<(), KubeletError> {
        Ok(())
    }
    async fn list_pod_sandbox(
        &self,
        _f: Option<&cri::PodSandboxFilter>,
    ) -> Result<Vec<cri::PodSandbox>, KubeletError> {
        Ok(Vec::new())
    }
    async fn pod_sandbox_status(&self, id: &str) -> Result<cri::PodSandboxStatus, KubeletError> {
        Ok(cri::PodSandboxStatus {
            id: id.to_string(),
            ..cri::PodSandboxStatus::default()
        })
    }
    async fn create_container(
        &self,
        _sandbox: &str,
        _c: &cri::ContainerConfig,
        _s: &cri::PodSandboxConfig,
    ) -> Result<String, KubeletError> {
        Ok("container".to_string())
    }
    async fn start_container(&self, _id: &str) -> Result<(), KubeletError> {
        Ok(())
    }
    async fn stop_container(&self, _id: &str, _timeout: i64) -> Result<(), KubeletError> {
        Ok(())
    }
    async fn remove_container(&self, _id: &str) -> Result<(), KubeletError> {
        Ok(())
    }
    async fn list_containers(
        &self,
        _f: Option<&cri::ContainerFilter>,
    ) -> Result<Vec<cri::Container>, KubeletError> {
        Ok(Vec::new())
    }
    async fn container_status(&self, id: &str) -> Result<cri::ContainerStatus, KubeletError> {
        Ok(cri::ContainerStatus {
            id: id.to_string(),
            ..cri::ContainerStatus::default()
        })
    }
    async fn exec_sync(
        &self,
        _id: &str,
        _cmd: &[String],
        _timeout: i64,
    ) -> Result<dioramalet::ExecResult, KubeletError> {
        Ok(dioramalet::ExecResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
    async fn container_logs(
        &self,
        _id: &str,
        _o: &dioramalet::LogOptions,
    ) -> Result<String, KubeletError> {
        Ok(String::new())
    }
    async fn image_status(&self, _i: &cri::ImageSpec) -> Result<Option<cri::Image>, KubeletError> {
        Ok(None)
    }
    async fn pull_image(
        &self,
        image: &cri::ImageSpec,
        _s: Option<&cri::PodSandboxConfig>,
    ) -> Result<String, KubeletError> {
        Ok(image.image.clone())
    }
}
