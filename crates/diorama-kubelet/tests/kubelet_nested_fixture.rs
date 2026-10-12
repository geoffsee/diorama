use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use dioramalet::{
    CgroupSetupStatus, ContainerEnvironment, Ipv6DisableStatus, KubeletCgroupVersion,
    KubeletConfigOptions, KubeletError, KubeletService, MockRuntimeProvider,
    MountPropagationStatus,
};
use tempfile::{TempDir, tempdir};

/// Disposable nested-runtime fixture providing isolated directories for cgroups,
/// mounts, sysctl, PKI, and storage without requiring any host mutations.
#[derive(Debug)]
struct DisposableNestedRuntimeFixture {
    pub dir: TempDir,
    pub pki_dir: PathBuf,
    pub datastore_dir: PathBuf,
    pub cgroup_dir: PathBuf,
    pub proc_ipv6_dir: PathBuf,
    pub kubelet_dir: PathBuf,
}

impl Default for DisposableNestedRuntimeFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl DisposableNestedRuntimeFixture {
    fn new() -> Self {
        let dir = tempdir().expect("failed to create temp dir for nested fixture");
        let root = dir.path();

        let pki_dir = root.join("pki");
        let datastore_dir = root.join("datastore");
        let cgroup_dir = root.join("cgroup");
        let proc_ipv6_dir = root.join("proc_net_ipv6");
        let kubelet_dir = root.join("kubelet");

        fs::create_dir_all(&pki_dir).unwrap();
        fs::create_dir_all(&datastore_dir).unwrap();
        fs::create_dir_all(&cgroup_dir).unwrap();
        fs::create_dir_all(&proc_ipv6_dir).unwrap();
        fs::create_dir_all(&kubelet_dir).unwrap();

        Self {
            dir,
            pki_dir,
            datastore_dir,
            cgroup_dir,
            proc_ipv6_dir,
            kubelet_dir,
        }
    }

    /// Configures simulated cgroup v2 environment with specified available controllers.
    fn setup_cgroup_v2(&self, controllers: &[&str]) {
        let controllers_path = self.cgroup_dir.join("cgroup.controllers");
        fs::write(&controllers_path, format!("{}\n", controllers.join(" "))).unwrap();
        let subtree_path = self.cgroup_dir.join("cgroup.subtree_control");
        fs::write(&subtree_path, "").unwrap();
    }

    /// Configures simulated cgroup v1 environment (no cgroup.controllers).
    fn setup_cgroup_v1(&self) {
        let controllers_path = self.cgroup_dir.join("cgroup.controllers");
        if controllers_path.exists() {
            let _ = fs::remove_file(controllers_path);
        }
    }

    /// Configures simulated IPv6 sysctls.
    fn setup_ipv6_sysctls(&self, initial_value: &str) {
        for target in ["all", "default", "lo"] {
            let target_dir = self.proc_ipv6_dir.join(target);
            fs::create_dir_all(&target_dir).unwrap();
            fs::write(
                target_dir.join("disable_ipv6"),
                format!("{initial_value}\n"),
            )
            .unwrap();
        }
    }

    /// Returns a simulated `ContainerEnvironment` bound strictly within this disposable fixture.
    fn container_environment(&self) -> ContainerEnvironment {
        ContainerEnvironment::new_simulated(
            self.dir.path().to_path_buf(),
            self.cgroup_dir.clone(),
            self.proc_ipv6_dir.clone(),
        )
    }

    /// Creates and initializes the API server, PKI, and `KubeletService` in container mode.
    async fn boot_kubelet(
        &self,
        node_name: &str,
        node_ip_str: &str,
        container_mode: bool,
        disable_ipv6: bool,
    ) -> Result<Arc<KubeletService>, KubeletError> {
        let node_ip: IpAddr = node_ip_str.parse().unwrap();

        let pki_config =
            ClusterPkiConfig::new(self.pki_dir.clone(), node_name.to_string(), node_ip);
        let pki = ClusterPki::new(pki_config);
        pki.reconcile()
            .map_err(|e| KubeletError::AuthenticationFailed {
                reason: format!("PKI reconcile failed: {e}"),
            })?;

        let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(self.datastore_dir.clone()))
            .map_err(|e| KubeletError::ApiserverUnavailable {
            reason: format!("datastore open failed: {e}"),
        })?;
        let storage = KubernetesStorage::new(engine.client(), "/registry");
        let apiserver_config = ApiserverConfig::default_for_pki(&self.pki_dir, node_ip);
        let apiserver_service = ApiserverService::new(apiserver_config, storage);
        apiserver_service.check_prerequisites().await.map_err(|e| {
            KubeletError::ApiserverUnavailable {
                reason: format!("apiserver prerequisites: {e}"),
            }
        })?;
        apiserver_service
            .start()
            .map_err(|e| KubeletError::ApiserverUnavailable {
                reason: format!("apiserver start: {e}"),
            })?;
        let apiserver = Arc::new(apiserver_service);

        let mock_runtime = Arc::new(MockRuntimeProvider::new("containerd"));
        let mut options = KubeletConfigOptions::default_for_pki(
            &self.pki_dir,
            node_name,
            node_ip_str,
            &self.kubelet_dir,
        );
        options.container_mode = container_mode;
        options.disable_ipv6 = disable_ipv6;

        let service = Arc::new(
            KubeletService::new(options, apiserver, mock_runtime)
                .with_container_environment(self.container_environment()),
        );

        service.start().await?;
        Ok(service)
    }
}

#[tokio::test]
async fn test_disposable_nested_runtime_fixture_cgroup_v2_boot() {
    let fixture = DisposableNestedRuntimeFixture::new();
    fixture.setup_cgroup_v2(&["cpu", "memory", "pids", "io"]);
    fixture.setup_ipv6_sysctls("0");

    assert_eq!(
        KubeletCgroupVersion::detect(&fixture.cgroup_dir),
        KubeletCgroupVersion::V2
    );

    // Boot Kubelet service in container mode inside disposable nested fixture
    let service = fixture
        .boot_kubelet("nested-node-v2", "192.0.2.55", true, true)
        .await
        .expect("nested container boot must succeed");

    assert!(service.is_running());

    // 1. Verify cgroup v2 setup occurred within fixture (PID moved and controllers enabled)
    let init_procs = fixture.cgroup_dir.join("init").join("cgroup.procs");
    assert!(
        init_procs.exists(),
        "cgroup init/cgroup.procs must be created"
    );
    let procs_content = fs::read_to_string(&init_procs).unwrap();
    assert_eq!(procs_content.trim(), std::process::id().to_string());

    let subtree = fixture.cgroup_dir.join("cgroup.subtree_control");
    let subtree_content = fs::read_to_string(&subtree).unwrap();
    assert!(subtree_content.contains("+cpu"));
    assert!(subtree_content.contains("+memory"));
    assert!(subtree_content.contains("+pids"));
    assert!(subtree_content.contains("+io"));

    // 2. Verify IPv6 sysctls were disabled within fixture
    for target in ["all", "default", "lo"] {
        let path = fixture.proc_ipv6_dir.join(target).join("disable_ipv6");
        let val = fs::read_to_string(&path).unwrap();
        assert_eq!(val.trim(), "1", "sysctl {target} must be set to 1");
    }

    // 3. Verify generated config in disposable kubelet directory
    let config_path = fixture.kubelet_dir.join("kubelet.yaml");
    assert!(config_path.exists());
    let config_content = fs::read_to_string(&config_path).unwrap();
    assert!(config_content.contains("cgroupsPerQOS: false\n"));
    assert!(config_content.contains("resolvConf: /dev/null\n"));
    assert!(config_content.contains("imageGCHighThresholdPercent: 100\n"));
    assert!(config_content.contains("memory.available: 50Mi\n"));

    // Verify removed edge overrides are NOT restored
    assert!(!config_content.contains("maxPods"));
    assert!(!config_content.contains("enableProfilingHandler"));

    // 4. Verify node health and readiness
    let health = service.check_readiness().await.unwrap();
    assert!(health.is_healthy);
    assert_eq!(health.node_name, "nested-node-v2");

    // 5. Verify workload execution (pod reconciliation) succeeds in container mode
    let pod_json = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "workload-in-container",
            "namespace": "default",
            "uid": "uid-workload-cgroup-v2"
        },
        "spec": {
            "nodeName": "nested-node-v2",
            "containers": [{
                "name": "app",
                "image": "busybox:latest"
            }]
        }
    });

    service
        .client()
        .create_pod("default", pod_json)
        .await
        .unwrap();

    let reconciled = service
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    assert_eq!(reconciled, 1);

    let pod_after = service
        .client()
        .get_pod("default", "workload-in-container")
        .await
        .unwrap();
    assert_eq!(pod_after["status"]["phase"], "Running");
}

#[tokio::test]
async fn test_disposable_nested_runtime_fixture_cgroup_v1_boot() {
    let fixture = DisposableNestedRuntimeFixture::new();
    fixture.setup_cgroup_v1();
    fixture.setup_ipv6_sysctls("1"); // Already disabled

    assert_eq!(
        KubeletCgroupVersion::detect(&fixture.cgroup_dir),
        KubeletCgroupVersion::V1
    );

    // Boot Kubelet service in container mode with cgroup v1
    let service = fixture
        .boot_kubelet("nested-node-v1", "192.0.2.56", true, true)
        .await
        .expect("nested container boot on cgroup v1 must succeed");

    assert!(service.is_running());

    // On cgroup v1, init cgroup should NOT be created
    let init_procs = fixture.cgroup_dir.join("init");
    assert!(
        !init_procs.exists(),
        "cgroup v1 must skip cgroup init/migration"
    );

    // Readiness and registration still succeed
    let health = service.check_readiness().await.unwrap();
    assert!(health.is_healthy);
}

#[tokio::test]
async fn test_disposable_nested_runtime_fixture_unprivileged_read_only_sysfs() {
    let fixture = DisposableNestedRuntimeFixture::new();
    // Do not create cgroup.controllers or proc_net_ipv6 paths, simulating an unprivileged or restricted environment
    let env = fixture.container_environment();

    // Mount propagation handles unprivileged without error
    let mount_status = env.prepare_mounts().unwrap();
    assert_eq!(mount_status, MountPropagationStatus::SimulatedRshared);

    // Cgroup setup on non-existent cgroup.controllers returns SkippedNotV2 without error
    let cgroup_status = env.prepare_cgroups(1234).unwrap();
    assert_eq!(cgroup_status, CgroupSetupStatus::SkippedNotV2);

    // IPv6 disablement on missing paths returns SkippedNotFound without error
    let ipv6_status = env.disable_ipv6().unwrap();
    assert_eq!(ipv6_status, Ipv6DisableStatus::SkippedNotFound);
}

#[tokio::test]
async fn test_disposable_nested_runtime_fixture_disallowed_host_mutations() {
    let fixture = DisposableNestedRuntimeFixture::new();
    fixture.setup_cgroup_v2(&["cpu", "memory"]);
    fixture.setup_ipv6_sysctls("0");

    let env = fixture
        .container_environment()
        .with_allow_host_mutations(false);
    assert!(!env.allow_host_mutations());

    let mount_status = env.prepare_mounts().unwrap();
    assert_eq!(mount_status, MountPropagationStatus::SimulatedRshared);

    let cgroup_status = env.prepare_cgroups(4321).unwrap();
    assert_eq!(
        cgroup_status,
        CgroupSetupStatus::Simulated {
            controllers: Vec::new(),
            pid: 4321,
        }
    );
    assert!(!fixture.cgroup_dir.join("init").exists());

    let ipv6_status = env.disable_ipv6().unwrap();
    assert_eq!(
        ipv6_status,
        Ipv6DisableStatus::SkippedHostMutationsDisallowed
    );
    let sysctl_val =
        fs::read_to_string(fixture.proc_ipv6_dir.join("all").join("disable_ipv6")).unwrap();
    assert_eq!(sysctl_val.trim(), "0");
}

#[tokio::test]
async fn test_nested_container_mode_rejects_static_cpu_manager() {
    let fixture = DisposableNestedRuntimeFixture::new();
    let node_ip: IpAddr = "192.0.2.60".parse().unwrap();

    let pki_config =
        ClusterPkiConfig::new(fixture.pki_dir.clone(), "reject-node".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().unwrap();

    let (engine, _) =
        DatastoreEngine::open(DatastoreConfig::new(fixture.datastore_dir.clone())).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");
    let apiserver_config = ApiserverConfig::default_for_pki(&fixture.pki_dir, node_ip);
    let apiserver_service = ApiserverService::new(apiserver_config, storage);
    apiserver_service.check_prerequisites().await.unwrap();
    apiserver_service.start().unwrap();
    let apiserver = Arc::new(apiserver_service);

    let mock_runtime = Arc::new(MockRuntimeProvider::new("containerd"));
    let mut options = KubeletConfigOptions::default_for_pki(
        &fixture.pki_dir,
        "reject-node",
        "192.0.2.60",
        &fixture.kubelet_dir,
    );
    options.container_mode = true;
    options.cpu_manager_policy = "static".to_string();

    let service = KubeletService::new(options, apiserver, mock_runtime)
        .with_container_environment(fixture.container_environment());

    let err = service
        .start()
        .await
        .expect_err("container mode must reject static CPU manager policy");
    match err {
        KubeletError::InvalidConfiguration { field, reason } => {
            assert_eq!(field, "cpu_manager_policy");
            assert!(reason.contains("static CPU manager policy is unsupported in container mode"));
        },
        other => panic!("expected InvalidConfiguration, got: {other:?}"),
    }
}
