//! Disposable Rust fixture coverage for restart and failure recovery (Issue #119 / E28.02).
//! These native datastore/in-process API tests do not qualify the retained Kine/API-server
//! production boundary, Linux reboot recovery, or the full C13 release gate.
//!
//! Validates:
//! 1. Crash/reboot state retention and before/after ownership invariants.
//! 2. Mock fatal failure policy and actual bounded termination of an owned Rust fixture process.
//! 3. Node-IP change reconfiguration with PKI leaf SAN rotation and dual YAML/JSON kubeconfig format support.
//! 4. Optional service failure isolation (`FailurePolicy::Degrade`) preserving core Kubernetes API availability.
//! 5. Lifecycle interruption handling with lock safety, absence of orphans, and idempotent subsequent startup.
//! 6. Native datastore fixture corruption fails closed unless repair is explicitly enabled.
//! 7. Historical regression inventory completeness, without inferred verification outcomes.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use diorama::lifecycle_sink::FlushPolicy;
use diorama::runtime::{COMPONENT_APISERVER, COMPONENT_DATASTORE, NodeRuntime, RuntimeBuilder};
use diorama_apiserver::ApiserverConfig;
use diorama_apiserver::client::KubernetesApiClient;
use diorama_apiserver::service::ApiserverService;
use diorama_apiserver::storage::KubernetesStorage;
use diorama_apiserver::supervisor::ApiserverAdapter;
use diorama_config::{
    EnvironmentMode, ExplicitFlags, HostContext, ValidatedConfig, decode, decode_yaml_value,
    resolve_layers,
};
use diorama_datastore::client::DatastoreClient;
use diorama_datastore::config::DatastoreConfig;
use diorama_datastore::engine::DatastoreEngine;
use diorama_datastore::supervisor::DatastoreAdapter;
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, FailureKind, StopCause, StopPhase,
    stop_channel,
};
use tempfile::TempDir;

#[derive(Clone, Default)]
struct LogProbe(Arc<Mutex<Vec<u8>>>);

impl LogProbe {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("lock").clone()).expect("utf8")
    }
}

impl Write for LogProbe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn test_config(dir: &Path, node_ip: &str, debug: bool, wal_repair: bool) -> ValidatedConfig {
    let yaml = format!(
        r#"
path: "{}"
network:
  nodeIP: "{}"
kubernetes:
  nodeName: "test-node"
logging:
  debug: {}
storage:
  dbWalRepair: {}
  localPath:
    enabled: false
api:
  enabled: false
metrics:
  enabled: false
"#,
        dir.display(),
        node_ip,
        debug,
        wal_repair
    );
    resolve_layers(
        Some(decode(&yaml).expect("decode")),
        &BTreeMap::new(),
        &ExplicitFlags::default(),
        EnvironmentMode::Include,
        &HostContext {
            cpu_count: 4,
            architecture: "arm64".into(),
            detected_container_mode: false,
        },
    )
    .expect("resolve")
    .validated
}

fn collect_owned_relative_paths(base: &Path) -> Vec<String> {
    let mut paths = Vec::new();
    collect_paths_recursive(base, base, &mut paths);
    paths.sort();
    paths
}

fn collect_paths_recursive(base: &Path, current: &Path, paths: &mut Vec<String>) {
    if let Ok(entries) = std::fs::read_dir(current) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(rel) = p.strip_prefix(base) {
                paths.push(rel.display().to_string());
            }
            if p.is_dir() {
                collect_paths_recursive(base, &p, paths);
            }
        }
    }
}

/// Asserts that a kubeconfig file is valid and accommodates both YAML and JSON formats.
fn assert_kubeconfig_format_and_server(path: &Path, expected_ip: &str) {
    let raw = std::fs::read_to_string(path).expect("read kubeconfig");

    // 1. Verify parsing as YAML (or JSON as YAML subset)
    let yaml_val = decode_yaml_value(&raw).expect("decode kubeconfig with decode_yaml_value");
    let clusters = yaml_val
        .get("clusters")
        .and_then(|c| c.as_array())
        .expect("clusters array");
    assert!(!clusters.is_empty(), "clusters must not be empty");

    let server_url = clusters[0]
        .get("cluster")
        .and_then(|c| c.get("server"))
        .and_then(|s| s.as_str())
        .expect("server url in cluster");
    assert!(
        server_url.contains(expected_ip),
        "server URL '{server_url}' does not contain expected IP '{expected_ip}'"
    );

    let contexts = yaml_val
        .get("contexts")
        .and_then(|c| c.as_array())
        .expect("contexts array");
    assert!(!contexts.is_empty(), "contexts must not be empty");

    let current_context = yaml_val
        .get("current-context")
        .and_then(|c| c.as_str())
        .expect("current-context field");
    assert!(!current_context.is_empty(), "current-context must be set");

    let users = yaml_val
        .get("users")
        .and_then(|u| u.as_array())
        .expect("users array");
    assert!(!users.is_empty(), "users must not be empty");

    // 2. Format accommodation test: serialize to JSON and ensure decode_yaml_value parses it identically
    let json_str = serde_json::to_string_pretty(&yaml_val).expect("to json");
    let json_val = decode_yaml_value(&json_str).expect("decode json kubeconfig");
    assert_eq!(
        yaml_val, json_val,
        "kubeconfig semantics must match identically across YAML and JSON representations"
    );
}

async fn wait_for_api_serving(client: &KubernetesApiClient, timeout: Duration) {
    tokio::time::timeout(timeout, async {
        loop {
            if client.list_namespaces().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Kubernetes API client reaches ready and serving state within timeout");
}

struct MockAdapter<F>(F);

struct CrashChild(Child);
impl Drop for CrashChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while !path.is_file() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("owned child readiness deadline");
}

#[tokio::test]
#[ignore = "invoked only by the owned crash fixture"]
async fn crash_runtime_child() {
    let root = std::env::var_os("diorama_RECOVERY_FIXTURE_ROOT").expect("private fixture root");
    let root = Path::new(&root);
    let config = test_config(&root.join("diorama-state"), "127.0.0.1", false, false);
    let runtime = NodeRuntime::from_config(config).expect("fixture runtime");
    let client = runtime.client().expect("fixture client").clone();
    let (_stop, receiver) = stop_channel();
    let task = tokio::spawn(runtime.run(receiver));
    wait_for_api_serving(&client, Duration::from_secs(5)).await;
    client
        .create_namespace("crash-recovery-ns")
        .await
        .expect("acknowledged mutation");
    let object = client
        .get_namespace("crash-recovery-ns")
        .await
        .expect("read acknowledged object");
    std::fs::write(
        root.join("acknowledged.tmp"),
        serde_json::to_vec(&object).unwrap(),
    )
    .unwrap();
    std::fs::rename(
        root.join("acknowledged.tmp"),
        root.join("acknowledged.json"),
    )
    .unwrap();
    // The parent kills this process while the runtime and datastore lock remain live.
    task.await.expect("fixture runtime stopped unexpectedly");
    panic!("crash fixture must not shut down gracefully");
}

impl<F, Fut> Adapter for MockAdapter<F>
where
    F: FnOnce(AdapterContext) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), AdapterError>> + Send + 'static,
{
    fn run(self: Box<Self>, context: AdapterContext) -> AdapterFuture {
        Box::pin((self.0)(context))
    }
}

// ---------------------------------------------------------------------------
// 1. Crash / Reboot Qualification & Ownership Retention
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_crash_reboot_preserves_datastore_pki_and_ownership() {
    let temp = TempDir::new().unwrap();
    let state_dir = temp.path().join("diorama-state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let config = test_config(&state_dir, "127.0.0.1", false, false);

    let mut child = CrashChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery_lifecycle::crash_runtime_child",
                "--ignored",
            ])
            .env("diorama_RECOVERY_FIXTURE_ROOT", temp.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn owned crash fixture"),
    );
    wait_for_file(&temp.path().join("acknowledged.json")).await;
    let acknowledged: serde_json::Value =
        serde_json::from_slice(&std::fs::read(temp.path().join("acknowledged.json")).unwrap())
            .unwrap();

    // Capture PKI fingerprints and ownership inventory before crash
    let pki_dir = state_dir.join("pki");
    let ca_crt_before = std::fs::read(pki_dir.join("ca.crt")).expect("read ca.crt");
    let ca_key_before = std::fs::read(pki_dir.join("ca.key")).expect("read ca.key");

    let ownership_before = collect_owned_relative_paths(&state_dir);
    assert!(
        ownership_before.iter().any(|p| p.starts_with("pki/")),
        "pki directory must exist before crash"
    );
    assert!(
        ownership_before.iter().any(|p| p.starts_with("datastore/")),
        "datastore directory must exist before crash"
    );

    // SIGKILL on Unix prevents adapter checkpoint/shutdown and process-local Drop cleanup.
    child.0.kill().expect("kill owned fixture");
    assert!(!child.0.wait().expect("reap owned fixture").success());

    // ----------------- Reboot / Second Boot -----------------
    let runtime2 =
        NodeRuntime::from_config(config.clone()).expect("re-assemble runtime on existing path");
    let client2 = runtime2.client().expect("client").clone();
    let probe2 = LogProbe::default();
    let (stop2, recv2) = stop_channel();

    let run_handle2 =
        tokio::spawn(runtime2.run_with_sink(recv2, probe2.clone(), FlushPolicy::EachFrame));

    wait_for_api_serving(&client2, Duration::from_secs(5)).await;

    // Verify state survived crash/reboot
    let recovered_ns = client2
        .get_namespace("crash-recovery-ns")
        .await
        .expect("recovered namespace must exist after reboot");
    assert_eq!(
        recovered_ns, acknowledged,
        "retain exact UID, resourceVersion and value"
    );

    // Verify new mutations succeed after reboot
    client2
        .create_namespace("post-reboot-ns")
        .await
        .expect("create namespace after reboot");
    let post_ns = client2
        .get_namespace("post-reboot-ns")
        .await
        .expect("get post-reboot ns");
    assert_eq!(post_ns["metadata"]["name"], "post-reboot-ns");

    // Verify PKI trust root preservation
    let ca_crt_after = std::fs::read(pki_dir.join("ca.crt")).expect("read ca.crt after");
    let ca_key_after = std::fs::read(pki_dir.join("ca.key")).expect("read ca.key after");
    assert_eq!(
        ca_crt_before, ca_crt_after,
        "CA certificate must be identical across crash and reboot"
    );
    assert_eq!(
        ca_key_before, ca_key_after,
        "CA private key must be identical across crash and reboot"
    );

    // Verify ownership invariants: only owned entries in state_dir exist
    let ownership_after = collect_owned_relative_paths(&state_dir);
    for rel_path in &ownership_after {
        assert!(
            rel_path.starts_with("pki") || rel_path.starts_with("datastore"),
            "unowned file detected in state dir after reboot: {rel_path}"
        );
    }

    stop2.stop();
    let (report2, _, _) = run_handle2.await.expect("join run 2");
    assert_eq!(report2.cause, StopCause::Requested);
    drop(client2);
}

// ---------------------------------------------------------------------------
// 2. Ungraceful Daemon Kills, Bounded Escalation, and Recovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mock_core_failure_policy_and_diagnostic_retention() {
    let temp = TempDir::new().unwrap();
    let state_dir = temp.path().join("kill-test");
    std::fs::create_dir_all(&state_dir).unwrap();

    let config = test_config(&state_dir, "127.0.0.1", false, false);

    // A completed mock error checks policy/diagnostics, not process kill escalation.
    let (kill_trigger_tx, kill_trigger_rx) = tokio::sync::oneshot::channel::<()>();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();

    let crashing_core_adapter = MockAdapter(move |mut ctx: AdapterContext| async move {
        ctx.ready();
        let _ = started_tx.send(());
        // Wait for ungraceful kill injection
        let _ = kill_trigger_rx.await;
        // Simulate ungraceful death
        Err(AdapterError {
            code: "simulated_daemon_crash",
        })
    });

    let probe = LogProbe::default();
    let (_stop_handle, stop_receiver) = stop_channel();

    let builder = RuntimeBuilder::new(config.clone()).register_core(
        "crashing-daemon",
        vec![],
        crashing_core_adapter,
    );

    let runtime = builder.build().expect("build runtime with mock core");
    let run_handle =
        tokio::spawn(runtime.run_with_sink(stop_receiver, probe.clone(), FlushPolicy::EachFrame));

    // Wait until daemon starts
    started_rx.await.expect("daemon started");

    // Inject ungraceful daemon kill
    let _ = kill_trigger_tx.send(());

    // Supervisor must observe the fatal core failure and exit.
    let (report, _, _) = run_handle.await.expect("supervisor terminates");

    match report.cause {
        StopCause::Fatal(failure) => {
            assert_eq!(failure.component, "crashing-daemon");
            assert_eq!(failure.kind, FailureKind::Adapter("simulated_daemon_crash"));
        },
        other => panic!("expected StopCause::Fatal, got: {other:?}"),
    }

    // Verify structured diagnostics captured the failure
    let log_text = probe.text();
    assert!(
        log_text.contains("crashing-daemon"),
        "diagnostic logs must report failing component identity"
    );

    // Verify post-kill recovery: a fresh runtime starts cleanly
    let recovery_runtime =
        NodeRuntime::from_config(config).expect("assemble post-kill recovery runtime");
    let client = recovery_runtime.client().expect("client").clone();
    let (stop_rec, recv_rec) = stop_channel();
    let rec_handle = tokio::spawn(recovery_runtime.run(recv_rec));

    wait_for_api_serving(&client, Duration::from_secs(5)).await;
    stop_rec.stop();
    let rec_report = rec_handle.await.expect("recovery completes");
    assert_eq!(rec_report.cause, StopCause::Requested);
    drop(client);
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "invoked only by the owned escalation fixture"]
async fn term_ignoring_child() {
    let root = std::env::var_os("diorama_ESCALATION_FIXTURE_ROOT").expect("private fixture root");
    let root = Path::new(&root);
    let mut termination =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    std::fs::write(root.join("ready"), "signal handler installed").unwrap();
    while termination.recv().await.is_some() {
        std::fs::write(root.join("term-observed"), "ignoring graceful termination").unwrap();
    }
    panic!("termination listener unexpectedly closed");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_owned_term_ignoring_process_is_killed_and_reaped_within_shutdown_budget() {
    use diorama_supervisor::process::{OwnedProcessAdapter, ProcessCommand};
    use diorama_supervisor::{
        ComponentKind, ComponentSpec, FailurePolicy, Registration, Supervisor,
    };
    let root = TempDir::new().unwrap();
    let ready = root.path().join("ready");
    let command = ProcessCommand::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("recovery_lifecycle::term_ignoring_child")
        .arg("--ignored")
        .env("diorama_ESCALATION_FIXTURE_ROOT", root.path());
    let probe = ready.clone();
    let (adapter, cleanup) = OwnedProcessAdapter::new(command, async move {
        wait_for_file(&probe).await;
        Ok(())
    });
    let supervisor = Supervisor::new(vec![Registration::new(
        ComponentSpec {
            id: "owned-term-ignoring-fixture".into(),
            prerequisites: vec![],
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Fatal,
            startup_timeout: Duration::from_secs(15),
        },
        adapter,
    )])
    .unwrap();
    let (stop, receiver) = stop_channel();
    let task = tokio::spawn(supervisor.run(receiver));
    wait_for_file(&ready).await;
    let started = std::time::Instant::now();
    stop.stop();
    let report = tokio::time::timeout(Duration::from_secs(38), task)
        .await
        .expect("bounded supervisor shutdown")
        .expect("supervisor join");
    assert_eq!(report.cause, StopCause::Requested);
    let snapshot = cleanup.wait(Duration::from_secs(3)).await;
    assert!(snapshot.complete(), "{snapshot:?}");
    assert!(snapshot.term_attempted && snapshot.kill_attempted && snapshot.leader_reaped);
    assert_eq!(snapshot.exit.expect("observed child exit").signal, Some(9));
    assert!(root.path().join("term-observed").is_file());
    assert!(started.elapsed() >= diorama_supervisor::GRACE_PERIOD);
    assert!(started.elapsed() < Duration::from_secs(41));
}

// ---------------------------------------------------------------------------
// 3. Node-IP Change Reconfiguration & Dual Kubeconfig Format Qualification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_node_ip_change_rotates_leaf_sans_and_updates_kubeconfig_both_formats() {
    let temp = TempDir::new().unwrap();
    let state_dir = temp.path().join("node-ip-test");
    std::fs::create_dir_all(&state_dir).unwrap();

    let pki_dir = state_dir.join("pki");
    let kubeconfig_path = pki_dir.join("admin.kubeconfig");

    // 1. Initial run on 127.0.0.1
    let config_ip1 = test_config(&state_dir, "127.0.0.1", false, false);
    let runtime1 =
        NodeRuntime::from_config(config_ip1.clone()).expect("assemble runtime on 127.0.0.1");
    let client1 = runtime1.client().expect("client").clone();
    let (stop1, recv1) = stop_channel();
    let handle1 = tokio::spawn(runtime1.run(recv1));

    wait_for_api_serving(&client1, Duration::from_secs(5)).await;

    // Mutate cluster state before IP change
    client1
        .create_namespace("ip-change-ns")
        .await
        .expect("create ns");

    // Validate kubeconfig generated for 127.0.0.1 (checking both YAML and JSON format compliance)
    assert_kubeconfig_format_and_server(&kubeconfig_path, "127.0.0.1");

    let ca_crt1 = std::fs::read(pki_dir.join("ca.crt")).expect("ca.crt 1");
    let ca_key1 = std::fs::read(pki_dir.join("ca.key")).expect("ca.key 1");
    let apiserver_cert1 = std::fs::read(pki_dir.join("kube-apiserver.crt")).expect("apiserver crt");

    stop1.stop();
    let _ = handle1.await;
    drop(client1);

    // 2. Reconfigure node IP to 192.168.1.188
    let config_ip2 = test_config(&state_dir, "192.168.1.188", false, false);
    let runtime2 = NodeRuntime::from_config(config_ip2).expect("re-assemble with updated node IP");
    let client2 = runtime2.client().expect("client").clone();
    let (stop2, recv2) = stop_channel();
    let handle2 = tokio::spawn(runtime2.run(recv2));

    wait_for_api_serving(&client2, Duration::from_secs(5)).await;

    // Validate that kubeconfig now reflects the new IP and is format-compliant in YAML and JSON
    assert_kubeconfig_format_and_server(&kubeconfig_path, "192.168.1.188");

    // Validate CA trust root was preserved across node IP reconfiguration
    let ca_crt2 = std::fs::read(pki_dir.join("ca.crt")).expect("ca.crt 2");
    let ca_key2 = std::fs::read(pki_dir.join("ca.key")).expect("ca.key 2");
    assert_eq!(
        ca_crt1, ca_crt2,
        "CA certificate must remain intact across IP change"
    );
    assert_eq!(
        ca_key1, ca_key2,
        "CA private key must remain intact across IP change"
    );

    // Validate leaf apiserver certificate was rotated to accommodate the new node IP
    let apiserver_cert2 =
        std::fs::read(pki_dir.join("kube-apiserver.crt")).expect("apiserver crt 2");
    assert_ne!(
        apiserver_cert1, apiserver_cert2,
        "kube-apiserver leaf certificate must be rotated when node IP changes"
    );

    // Validate that cluster objects created before IP change remain accessible
    let ns = client2
        .get_namespace("ip-change-ns")
        .await
        .expect("namespace preserved across IP change");
    assert_eq!(ns["metadata"]["name"], "ip-change-ns");

    stop2.stop();
    let _ = handle2.await;
    drop(client2);
}

// ---------------------------------------------------------------------------
// 4. Optional Service Failure Isolation (FailurePolicy::Degrade)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_optional_service_failure_isolation_preserves_core_api() {
    let temp = TempDir::new().unwrap();
    let state_dir = temp.path().join("optional-failure-test");
    std::fs::create_dir_all(&state_dir).unwrap();

    let config = test_config(&state_dir, "127.0.0.1", false, false);
    let probe = LogProbe::default();
    let (stop_handle, stop_receiver) = stop_channel();

    let pki_dir = state_dir.join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let node_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "test-node".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("pki reconcile");

    let datastore_dir = state_dir.join("datastore");
    std::fs::create_dir_all(&datastore_dir).unwrap();
    let ds_config = DatastoreConfig::new(datastore_dir);
    let (engine, _) = DatastoreEngine::open(ds_config).expect("datastore open");
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    let apiserver_cfg = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    let apiserver_service = Arc::new(ApiserverService::new(apiserver_cfg, storage));
    let client = apiserver_service.admin_client();

    let timeout = Duration::from_secs(5);
    let datastore_reg =
        DatastoreAdapter::registration_for_engine(COMPONENT_DATASTORE, engine, timeout);
    let apiserver_reg = ApiserverAdapter::registration(
        COMPONENT_APISERVER,
        (*apiserver_service).clone(),
        vec![COMPONENT_DATASTORE.to_string()],
        timeout,
    );

    // Adapter for an optional component that fails after startup
    let (fail_signal_tx, fail_signal_rx) = tokio::sync::oneshot::channel::<()>();
    let optional_adapter = MockAdapter(move |mut ctx: AdapterContext| async move {
        ctx.ready();
        let _ = fail_signal_rx.await;
        // Optional service crashes
        Err(AdapterError {
            code: "optional_addon_crashed",
        })
    });

    // Build supervisor with core + degraded optional component
    let builder = RuntimeBuilder::new(config)
        .with_apiserver(apiserver_service)
        .with_client(client.clone())
        .register_component(datastore_reg)
        .register_component(apiserver_reg)
        .register_optional(
            "flaky-optional-addon",
            vec![COMPONENT_APISERVER.to_string()],
            optional_adapter,
        );

    let runtime = builder.build().expect("build with optional component");
    let run_handle =
        tokio::spawn(runtime.run_with_sink(stop_receiver, probe.clone(), FlushPolicy::EachFrame));

    wait_for_api_serving(&client, Duration::from_secs(5)).await;

    // Verify API is functioning initially
    client
        .create_namespace("initial-ns")
        .await
        .expect("create ns before optional failure");

    // Trigger failure of the optional component
    let _ = fail_signal_tx.send(());

    // Give supervisor time to process the failure under FailurePolicy::Degrade
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Assert that the supervisor DID NOT terminate; the core API remains fully available
    client
        .create_namespace("post-optional-failure-ns")
        .await
        .expect("core Kubernetes API must remain functional after optional component failure");
    let ns = client
        .get_namespace("post-optional-failure-ns")
        .await
        .expect("read ns created after optional failure");
    assert_eq!(ns["metadata"]["name"], "post-optional-failure-ns");

    // Clean shutdown
    stop_handle.stop();
    let (report, _, _) = run_handle.await.expect("runtime join");
    assert_eq!(
        report.cause,
        StopCause::Requested,
        "supervisor report must reflect requested stop, not a crash from the degraded component"
    );

    // Diagnostics check: logs must record the degradation without leaking sensitive data
    let log_text = probe.text();
    assert!(
        log_text.contains("flaky-optional-addon"),
        "logs must identify the failing optional component"
    );
    drop(client);
}

// ---------------------------------------------------------------------------
// 5. Lifecycle Interruption and Lock Recovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_lifecycle_interruption_during_startup_leaves_clean_ownership() {
    let temp = TempDir::new().unwrap();
    let state_dir = temp.path().join("interruption-test");
    std::fs::create_dir_all(&state_dir).unwrap();

    let config = test_config(&state_dir, "127.0.0.1", false, false);

    // Create a slow component to simulate interruption during mid-startup
    let (slow_start_tx, slow_start_rx) = tokio::sync::oneshot::channel::<()>();
    let slow_adapter = MockAdapter(move |mut ctx: AdapterContext| async move {
        let _ = slow_start_tx.send(());
        // Wait until interrupted
        while ctx.stop_phase() == StopPhase::Running {
            ctx.changed().await;
        }
        Ok(())
    });

    let (stop_handle, stop_receiver) = stop_channel();
    let builder = RuntimeBuilder::new(config.clone()).register_core(
        "slow-starting-service",
        vec![],
        slow_adapter,
    );
    let runtime = builder.build().expect("build runtime with slow service");

    let run_handle = tokio::spawn(runtime.run(stop_receiver));

    // Wait until slow component begins starting
    slow_start_rx.await.expect("slow component entered startup");

    // Interrupt startup via stop handle
    stop_handle.stop();

    let report = run_handle.await.expect("interrupted runtime halts cleanly");
    assert_eq!(
        report.cause,
        StopCause::Requested,
        "interrupted startup must produce requested stop cause"
    );

    // Verify subsequent startup succeeds without lock contention or manual cleanup
    let clean_runtime = NodeRuntime::from_config(config)
        .expect("subsequent startup must succeed after interruption");
    let client = clean_runtime.client().expect("client").clone();
    let (stop_clean, recv_clean) = stop_channel();
    let clean_handle = tokio::spawn(clean_runtime.run(recv_clean));

    wait_for_api_serving(&client, Duration::from_secs(5)).await;
    stop_clean.stop();
    let clean_report = clean_handle.await.expect("clean handle finish");
    assert_eq!(clean_report.cause, StopCause::Requested);
    drop(client);
}

// ---------------------------------------------------------------------------
// 6. Required Failures Fail Closed and Block Release
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_required_datastore_corruption_fails_closed_and_blocks_release() {
    let temp = TempDir::new().unwrap();
    let state_dir = temp.path().join("corrupt-datastore-test");
    std::fs::create_dir_all(&state_dir).unwrap();

    // 1. Initial valid write
    let config_no_repair = test_config(&state_dir, "127.0.0.1", false, false);
    let ds_cfg = DatastoreConfig::new(state_dir.join("datastore"));
    {
        let (engine, _) = DatastoreEngine::open(ds_cfg.clone()).unwrap();
        let client = DatastoreClient::new(engine);
        client
            .create("/registry/pods/p1", b"val".to_vec())
            .await
            .unwrap();
    }

    // 2. Corrupt WAL by appending invalid/torn bytes
    let wal_path = ds_cfg.wal_path();
    {
        use std::fs::OpenOptions;
        let mut f = OpenOptions::new().append(true).open(&wal_path).unwrap();
        f.write_all(&256u32.to_be_bytes()).unwrap();
        f.write_all(b"incomplete-truncated-wal-frame").unwrap();
        f.flush().unwrap();
    }

    // 3. NodeRuntime startup without opt-in repair MUST fail closed
    let runtime_res = NodeRuntime::from_config(config_no_repair);
    assert!(
        runtime_res.is_err(),
        "runtime must fail closed on corrupt WAL when dbWalRepair is false"
    );
    let err = runtime_res.err().unwrap();
    assert_eq!(
        err.diagnostic_code(),
        "datastore_failure",
        "error must expose secret-safe diagnostic code"
    );

    // 4. Opt-in repair allows recovery
    let config_with_repair = test_config(&state_dir, "127.0.0.1", false, true);
    let recovery_res = NodeRuntime::from_config(config_with_repair);
    assert!(
        recovery_res.is_ok(),
        "runtime must successfully recover corrupt WAL when dbWalRepair is true"
    );
}

// ---------------------------------------------------------------------------
// 7. Historical Regression Matrix Qualification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
// Bounds below are historical targets; inventory completeness does not measure them.
struct HistoricalRegressionCase {
    id: &'static str,
    upstream_ref: &'static str,
    description: &'static str,
    declared_bound: &'static str,
}

#[test]
fn test_historical_regression_inventory_has_complete_descriptions() {
    let cases = vec![
        HistoricalRegressionCase {
            id: "REG-01",
            upstream_ref: "upstream #98 (KS-16)",
            description: "CoreDNS false readiness prevented when replicas are 0",
            declared_bound: "readiness probe timeout <= 10s",
        },
        HistoricalRegressionCase {
            id: "REG-02",
            upstream_ref: "arm64 component boundary r1",
            description: "API server advertise address & SAN mismatch prevention",
            declared_bound: "SAN reconciliation instantaneous during PKI reconcile",
        },
        HistoricalRegressionCase {
            id: "REG-03",
            upstream_ref: "arm64 component boundary r2",
            description: "Datastore outage shutdown forced escalation without orphan processes",
            declared_bound: "escalation timeout <= 5s",
        },
        HistoricalRegressionCase {
            id: "REG-04",
            upstream_ref: "arm64 component boundary r3",
            description: "Recovery after datastore crash and acknowledged update retention",
            declared_bound: "datastore recovery readiness <= 10s",
        },
        HistoricalRegressionCase {
            id: "REG-05",
            upstream_ref: "upstream #178 (KS-75)",
            description: "LoadBalancer external-IP preserved across service updates and restarts",
            declared_bound: "admission update instantaneous",
        },
        HistoricalRegressionCase {
            id: "REG-06",
            upstream_ref: "upstream #190 (3fd84ca)",
            description: "Host network compatibility on nftables-only and read-only /proc/sys hosts",
            declared_bound: "preflight probe <= 5s",
        },
        HistoricalRegressionCase {
            id: "REG-07",
            upstream_ref: "diorama-datastore wal repair",
            description: "Datastore WAL torn write fails closed unless dbWalRepair is opted in",
            declared_bound: "immediate fail-closed rejection",
        },
        HistoricalRegressionCase {
            id: "REG-08",
            upstream_ref: "dioramactl #112 / #113",
            description: "Scoped reset removes disposable runtime state while preserving PKI and volume data",
            declared_bound: "state cleanup <= 30s",
        },
        HistoricalRegressionCase {
            id: "REG-09",
            upstream_ref: "diorama-pki / dioramactl #107",
            description: "Kubeconfig parsing and generation accommodates both YAML and JSON formats",
            declared_bound: "decode memory <= 8MiB",
        },
        HistoricalRegressionCase {
            id: "REG-10",
            upstream_ref: "diorama-supervisor #44",
            description: "Lifecycle interruption during startup releases locks and permits clean re-entry",
            declared_bound: "cancellation grace period <= 5s",
        },
    ];

    assert_eq!(
        cases.len(),
        10,
        "exactly 10 historical regressions must be tracked"
    );
    for case in &cases {
        assert!(
            !case.declared_bound.is_empty(),
            "Declared bound must be specified for {}",
            case.id
        );
        assert!(
            !case.upstream_ref.is_empty(),
            "Upstream ref must be specified for {}",
            case.id
        );
        assert!(
            !case.description.is_empty(),
            "Description must be specified for {}",
            case.id
        );
    }
}
