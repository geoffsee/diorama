use std::fs;
use std::sync::Arc;
use std::time::Duration;

use diorama_network::MockCommandExecutor;
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
