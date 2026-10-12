use std::fs;
use std::sync::Arc;
use std::time::Duration;

use diorama_apiserver::{ApiserverService, KubernetesApiClient};
use diorama_network::{CommandExecutor, MockCommandExecutor};
use diorama_proxy::{
    COMPONENT_PROXY, DEFAULT_STARTUP_TIMEOUT, KubeProxyOptions, ProxyAdapter, ProxyMode,
    ProxyService,
};
use diorama_supervisor::{
    Adapter, AdapterContext, AdapterFuture, ComponentKind, ComponentSpec, FailurePolicy,
    Registration, StopCause, Supervisor, stop_channel,
};
use tempfile::TempDir;

#[tokio::test]
async fn test_supervisor_adapter_lifecycle() {
    let temp = TempDir::new().unwrap();
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let mock = MockCommandExecutor::new_nftables_host();
    let options = KubeProxyOptions::new(
        kubeconfig,
        true, // container_mode = true
        ProxyMode::Nftables,
    );

    let service = ProxyService::new(options)
        .with_executor(Arc::new(mock))
        .with_sys_root(temp.path().to_path_buf());

    let reg = ProxyAdapter::registration(
        COMPONENT_PROXY,
        service.clone(),
        vec![],
        DEFAULT_STARTUP_TIMEOUT,
    );
    assert_eq!(reg.spec.failure_policy, FailurePolicy::Degrade);

    let supervisor = Supervisor::new(vec![reg]).expect("supervisor creation succeeds");
    let (stop_handle, stop_receiver) = stop_channel();
    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    // Allow supervisor to start proxy adapter and confirm readiness
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !service.is_running() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        service.is_running(),
        "Proxy service must be active after startup"
    );

    let report = service.check_readiness().unwrap();
    assert!(report.is_healthy);
    assert_eq!(report.proxy_mode, ProxyMode::Nftables);
    assert!(report.container_mode);
    assert!(report.all_conntrack_zero);

    stop_handle.stop();
    let report = sup_handle.await.expect("supervisor task joins");
    assert!(matches!(report.cause, StopCause::Requested));
    assert!(!service.is_running());
}

struct HoldReady;

impl Adapter for HoldReady {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            if !context.ready() {
                return Err(diorama_supervisor::AdapterError {
                    code: "hold-not-ready",
                });
            }
            while context.changed().await != diorama_supervisor::StopPhase::Force {
                if context.stop_phase() != diorama_supervisor::StopPhase::Running {
                    break;
                }
            }
            Ok(())
        })
    }
}

#[tokio::test]
async fn missing_kubeconfig_does_not_stop_the_supervisor() {
    let temp = TempDir::new().unwrap();
    let kubeconfig = temp.path().join("kube-proxy.kubeconfig");
    let mock = MockCommandExecutor::new_nftables_host();
    let options = KubeProxyOptions::new(kubeconfig, true, ProxyMode::Nftables);
    let service = ProxyService::new(options)
        .with_executor(Arc::new(mock))
        .with_sys_root(temp.path().to_path_buf());
    let proxy =
        ProxyAdapter::registration(COMPONENT_PROXY, service, vec![], DEFAULT_STARTUP_TIMEOUT);
    let api = Registration::new(
        ComponentSpec {
            id: "kube-apiserver".to_string(),
            prerequisites: Vec::new(),
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Fatal,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
        },
        HoldReady,
    );
    let supervisor = Supervisor::new(vec![api, proxy]).expect("supervisor creation succeeds");
    let (stop_handle, stop_receiver) = stop_channel();
    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !sup_handle.is_finished(),
        "missing kube-proxy credential must leave the API server running"
    );

    stop_handle.stop();
    let report = sup_handle.await.expect("supervisor task joins");
    assert!(matches!(report.cause, StopCause::Requested));
}

fn setup_test_cluster(dir: &TempDir) -> (ApiserverService, KubernetesApiClient) {
    let node_ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    fs::create_dir_all(&pki_dir).unwrap();
    let datastore_dir = dir.path().join("datastore");

    let pki_config = diorama_pki::cluster::ClusterPkiConfig::new(
        pki_dir.clone(),
        "test-node".to_string(),
        node_ip,
    );
    let pki = diorama_pki::cluster::ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    let (engine, _) = diorama_datastore::DatastoreEngine::open(
        diorama_datastore::DatastoreConfig::new(datastore_dir),
    )
    .unwrap();
    let storage = diorama_apiserver::KubernetesStorage::new(engine.client(), "/registry");

    let apiserver_config = diorama_apiserver::ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    let apiserver_service = diorama_apiserver::ApiserverService::new(apiserver_config, storage);
    let client = apiserver_service.admin_client();

    (apiserver_service, client)
}

#[tokio::test]
async fn test_iptables_proxy_installs_service_chains_when_clusterip_has_endpoints() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.start().unwrap();

    let proc_net = temp.path().join("proc/net");
    fs::create_dir_all(&proc_net).unwrap();
    fs::write(proc_net.join("ip_tables_names"), "filter\nnat\n").unwrap();

    let mock = Arc::new(MockCommandExecutor::new_iptables_host());
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let options = KubeProxyOptions::new(kubeconfig, true, ProxyMode::IpTables);
    let service = ProxyService::new(options)
        .with_executor(mock.clone())
        .with_sys_root(temp.path().to_path_buf())
        .with_client(Arc::new(client.clone()));

    let reg = ProxyAdapter::registration(
        COMPONENT_PROXY,
        service.clone(),
        vec![],
        DEFAULT_STARTUP_TIMEOUT,
    );
    let supervisor = Supervisor::new(vec![reg]).expect("supervisor creation succeeds");
    let (stop_handle, stop_receiver) = stop_channel();
    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    // Wait until proxy service starts
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !service.is_running() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(service.is_running(), "proxy service must be running");

    // Initially, base chains are present in iptables-save
    let initial_save = mock.run("iptables-save", &[]).unwrap();
    assert!(initial_save.stdout.contains(":KUBE-SERVICES"));
    assert!(initial_save.stdout.contains(":KUBE-NODEPORTS"));
    assert!(initial_save.stdout.contains(":KUBE-POSTROUTING"));

    // Create a Service with ClusterIP
    let svc = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "nginx",
            "namespace": "default"
        },
        "spec": {
            "type": "ClusterIP",
            "clusterIP": "10.43.0.123",
            "ports": [{
                "name": "http",
                "port": 80,
                "targetPort": 8080,
                "protocol": "TCP"
            }]
        }
    });
    client.create_service("default", svc).await.unwrap();

    // Create EndpointSlice with an endpoint
    let slice = serde_json::json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": "nginx-slice",
            "namespace": "default",
            "labels": {
                "kubernetes.io/service-name": "nginx"
            }
        },
        "addressType": "IPv4",
        "ports": [{
            "name": "http",
            "port": 8080,
            "protocol": "TCP"
        }],
        "endpoints": [{
            "addresses": ["10.42.0.77"],
            "conditions": {
                "ready": true
            }
        }]
    });
    client.create_endpointslice("default", slice).await.unwrap();

    // Wait for the Service chain to appear in iptables-save
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut verified = false;
    while tokio::time::Instant::now() < deadline {
        let save_out = mock.run("iptables-save", &[]).unwrap();
        if save_out.stdout.contains("10.43.0.123") && save_out.stdout.contains("10.42.0.77") {
            assert!(save_out.stdout.contains(":KUBE-SERVICES"));
            assert!(save_out.stdout.contains(":KUBE-SVC-"));
            assert!(save_out.stdout.contains(":KUBE-SEP-"));
            assert!(save_out.stdout.contains(
                "-A KUBE-SERVICES -d 10.43.0.123/32 -p tcp -m tcp --dport 80 -j KUBE-SVC-"
            ));
            verified = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        verified,
        "iptables-save must show the Service chains after a ClusterIP Service has an endpoint"
    );

    stop_handle.stop();
    let report = sup_handle.await.expect("supervisor task joins");
    assert!(matches!(report.cause, StopCause::Requested));
}

#[tokio::test]
async fn test_nftables_proxy_installs_service_chains_when_clusterip_has_endpoints() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.start().unwrap();

    let mock = Arc::new(MockCommandExecutor::new_nftables_host());
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let options = KubeProxyOptions::new(kubeconfig, true, ProxyMode::Nftables);
    let service = ProxyService::new(options)
        .with_executor(mock.clone())
        .with_sys_root(temp.path().to_path_buf())
        .with_client(Arc::new(client.clone()));

    let reg = ProxyAdapter::registration(
        COMPONENT_PROXY,
        service.clone(),
        vec![],
        DEFAULT_STARTUP_TIMEOUT,
    );
    let supervisor = Supervisor::new(vec![reg]).expect("supervisor creation succeeds");
    let (stop_handle, stop_receiver) = stop_channel();
    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    // Wait until proxy service starts
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !service.is_running() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(service.is_running(), "proxy service must be running");

    // Create a Service with ClusterIP
    let svc = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "web",
            "namespace": "default"
        },
        "spec": {
            "type": "ClusterIP",
            "clusterIP": "10.43.0.88",
            "ports": [{
                "name": "http",
                "port": 80,
                "targetPort": 8080,
                "protocol": "TCP"
            }]
        }
    });
    client.create_service("default", svc).await.unwrap();

    // Create EndpointSlice with an endpoint
    let slice = serde_json::json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": "web-slice",
            "namespace": "default",
            "labels": {
                "kubernetes.io/service-name": "web"
            }
        },
        "addressType": "IPv4",
        "ports": [{
            "name": "http",
            "port": 8080,
            "protocol": "TCP"
        }],
        "endpoints": [{
            "addresses": ["10.42.0.99"],
            "conditions": {
                "ready": true
            }
        }]
    });
    client.create_endpointslice("default", slice).await.unwrap();

    // Verify nft list ruleset shows the Service chains and rules
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut verified = false;
    while tokio::time::Instant::now() < deadline {
        let ruleset_out = mock.run("nft", &["list", "ruleset"]).unwrap();
        if ruleset_out.stdout.contains("10.43.0.88") && ruleset_out.stdout.contains("10.42.0.99") {
            assert!(ruleset_out.stdout.contains("chain services"));
            assert!(
                ruleset_out
                    .stdout
                    .contains("ip daddr 10.43.0.88 tcp dport 80 dnat to 10.42.0.99:8080")
            );
            verified = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        verified,
        "nft list ruleset must show the Service chains after a ClusterIP Service has an endpoint"
    );

    stop_handle.stop();
    let report = sup_handle.await.expect("supervisor task joins");
    assert!(matches!(report.cause, StopCause::Requested));
}

struct FailingPacketFilterExecutor {
    inner: MockCommandExecutor,
}

impl diorama_network::CommandExecutor for FailingPacketFilterExecutor {
    fn run(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<diorama_network::CommandOutput, std::io::Error> {
        if program == "iptables" && args.contains(&"-S") {
            return Ok(diorama_network::CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "iptables: Operation not permitted".to_string(),
            });
        }
        self.inner.run(program, args)
    }
}

#[tokio::test]
async fn test_proxy_degrades_when_packet_filter_fails_and_api_stays_healthy() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.start().unwrap();

    let proc_net = temp.path().join("proc/net");
    fs::create_dir_all(&proc_net).unwrap();
    fs::write(proc_net.join("ip_tables_names"), "filter\nnat\n").unwrap();

    let failing_mock = Arc::new(FailingPacketFilterExecutor {
        inner: MockCommandExecutor::new_iptables_host(),
    });
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let options = KubeProxyOptions::new(kubeconfig, true, ProxyMode::IpTables);
    let service = ProxyService::new(options)
        .with_executor(failing_mock)
        .with_sys_root(temp.path().to_path_buf())
        .with_client(Arc::new(client.clone()));

    let proxy_reg = ProxyAdapter::registration(
        COMPONENT_PROXY,
        service.clone(),
        vec![],
        DEFAULT_STARTUP_TIMEOUT,
    );
    let api_reg = Registration::new(
        ComponentSpec {
            id: "kube-apiserver".to_string(),
            prerequisites: Vec::new(),
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Fatal,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
        },
        HoldReady,
    );

    let supervisor =
        Supervisor::new(vec![api_reg, proxy_reg]).expect("supervisor creation succeeds");
    let (supervisor, mut observer) = supervisor.with_observer();
    let (stop_handle, stop_receiver) = stop_channel();
    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    // Wait until degraded state is observed
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut degraded_recorded = false;
    while tokio::time::Instant::now() < deadline {
        let snapshot = observer.snapshot();
        if snapshot.degraded {
            degraded_recorded = true;
            let has_proxy_failure = snapshot.failures.iter().any(|f| {
                f.component == COMPONENT_PROXY
                    && matches!(
                        f.kind,
                        diorama_supervisor::FailureKind::Adapter("proxy-command-failed")
                    )
            });
            assert!(
                has_proxy_failure,
                "degraded failure kind must record proxy-command-failed"
            );
            break;
        }
        let _ = tokio::time::timeout(Duration::from_millis(50), observer.changed()).await;
    }
    assert!(
        degraded_recorded,
        "supervisor must record degraded state when packet filter fails"
    );

    // The supervisor must NOT have finished/crashed: API server stays up!
    assert!(
        !sup_handle.is_finished(),
        "supervisor must keep API server running despite proxy degradation"
    );

    // Verify the Kubernetes API client remains completely healthy and responsive
    let discovery = client
        .discover_core()
        .expect("API server must stay up and responsive");
    assert_eq!(discovery["kind"], "APIResourceList");

    stop_handle.stop();
    let report = sup_handle.await.expect("supervisor task joins");
    assert!(matches!(report.cause, StopCause::Requested));
}
