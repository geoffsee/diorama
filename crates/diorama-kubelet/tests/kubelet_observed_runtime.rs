//! Pod status must follow what the CRI runtime reports: Pending while nothing
//! runs, Running while a container is alive or restarting, then Succeeded or
//! Failed from the exit code under the restart policy. Deleted pods are stopped
//! with the grace period, their sandbox removed, and the object deleted.

use std::net::IpAddr;
use std::sync::Arc;

use serde_json::{Value, json};
use tempfile::TempDir;

use diorama_apiserver::{
    ApiserverConfig, ApiserverService, KubernetesApiClient, KubernetesStorage, PodExec,
    PodLogOptions, PodLogReader,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use dioramalet::{
    CriRuntimeProvider, KubeletConfigOptions, KubeletService, MockRuntimeProvider, RuntimeProvider,
};

fn setup(dir: &TempDir) -> (Arc<ApiserverService>, KubeletConfigOptions) {
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    ClusterPki::new(ClusterPkiConfig::new(
        pki_dir.clone(),
        "test-node".to_string(),
        node_ip,
    ))
    .reconcile()
    .unwrap();
    let (engine, _) =
        DatastoreEngine::open(DatastoreConfig::new(dir.path().join("datastore"))).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");
    let apiserver =
        ApiserverService::new(ApiserverConfig::default_for_pki(&pki_dir, node_ip), storage);
    let kubelet_dir = dir.path().join("kubelet");
    std::fs::create_dir_all(&kubelet_dir).unwrap();
    let options =
        KubeletConfigOptions::default_for_pki(&pki_dir, "test-node", "192.0.2.1", &kubelet_dir);
    (Arc::new(apiserver), options)
}

fn pod_with_policy(name: &str, policy: &str) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": name, "namespace": "default" },
        "spec": {
            "restartPolicy": policy,
            "containers": [{
                "name": "hello",
                "image": "localhost/diorama-hello:latest",
                "command": ["/diorama-hello"]
            }]
        }
    })
}

fn one_shot_pod(name: &str) -> Value {
    pod_with_policy(name, "Never")
}

fn phase(pod: &Value) -> &str {
    pod["status"]["phase"].as_str().unwrap_or("")
}

fn condition<'a>(pod: &'a Value, kind: &str) -> &'a Value {
    pod["status"]["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == kind)
        .unwrap_or_else(|| panic!("condition {kind}"))
}

struct Started {
    _dir: TempDir,
    kubelet: KubeletService,
    admin: KubernetesApiClient,
    runtime: Arc<MockRuntimeProvider>,
}

/// Binds Pods through the scheduler endpoint before running the kubelet.
async fn start_pods(pods: Vec<Value>) -> Started {
    let dir = TempDir::new().unwrap();
    let (apiserver, options) = setup(&dir);
    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let runtime = Arc::new(MockRuntimeProvider::new("mock"));
    let kubelet = KubeletService::new(options, apiserver.clone(), runtime.clone());
    kubelet.start().await.unwrap();
    let admin = apiserver.admin_client();
    let count = pods.len();
    for pod in pods {
        let pod = admin.create_pod("default", pod).await.unwrap();
        admin
            .bind_pod(
                "default",
                pod["metadata"]["name"].as_str().unwrap(),
                json!({"target":{"kind":"Node","name":"test-node"}}),
            )
            .await
            .unwrap();
    }
    let report = kubelet.reconcile_once().await.unwrap();
    assert_eq!((report.bound, report.synced, report.failed), (0, count, 0));
    Started {
        _dir: dir,
        kubelet,
        admin,
        runtime,
    }
}

async fn uid_of(admin: &KubernetesApiClient, name: &str) -> String {
    admin.get_pod("default", name).await.unwrap()["metadata"]["uid"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn resource_version(admin: &KubernetesApiClient, name: &str) -> Value {
    admin.get_pod("default", name).await.unwrap()["metadata"]["resourceVersion"].clone()
}

#[tokio::test]
async fn api_bound_pod_is_started_and_reported_running() {
    let Started {
        kubelet,
        admin,
        runtime,
        ..
    } = start_pods(vec![one_shot_pod("ok")]).await;

    let ok = admin.get_pod("default", "ok").await.unwrap();
    assert_eq!(ok["spec"]["nodeName"], "test-node");
    assert_eq!(phase(&ok), "Running");
    let uid = uid_of(&admin, "ok").await;
    let status = &ok["status"]["containerStatuses"][0];
    assert_eq!(status["containerID"], "mock://mock-c-2");
    assert_eq!(
        status["imageID"],
        "sha256:mock-localhost/diorama-hello:latest"
    );
    assert_eq!(status["ready"], true);
    assert_eq!(status["restartCount"], 0);
    assert!(status["state"]["running"]["startedAt"].is_string());
    assert_eq!(ok["status"]["podIP"], "192.0.2.1");
    for kind in [
        "PodReadyToStartContainers",
        "Initialized",
        "Ready",
        "ContainersReady",
        "PodScheduled",
    ] {
        let c = condition(&ok, kind);
        assert_eq!(c["status"], "True", "{kind}");
        assert!(c["lastTransitionTime"].is_string(), "{kind}");
    }
    assert!(runtime.is_pod_active(&uid));
    assert_eq!(runtime.container_ids(&uid).len(), 1);

    // Logs are read through the kubelet for the stored pod object, with options.
    runtime.set_container_logs("hello", "diorama-ok\nline 2\nline 3\n");
    let options = PodLogOptions {
        tail_lines: Some(2),
        ..PodLogOptions::default()
    };
    let text = kubelet
        .log_source()
        .read_pod_log(&ok, &options)
        .await
        .unwrap();
    assert_eq!(text, "line 2\nline 3\n");

    // Nothing changed, so a second pass writes no status and starts nothing new.
    let before = resource_version(&admin, "ok").await;
    kubelet.reconcile_once().await.unwrap();
    assert_eq!(before, resource_version(&admin, "ok").await);
    assert_eq!(runtime.container_ids(&uid).len(), 1);

    // A pod assigned elsewhere is ignored.
    let mut elsewhere = one_shot_pod("elsewhere");
    elsewhere["spec"]["nodeName"] = json!("other-node");
    admin.create_pod("default", elsewhere).await.unwrap();
    let report = kubelet.reconcile_once().await.unwrap();
    assert_eq!(report.bound, 0);
    let elsewhere = admin.get_pod("default", "elsewhere").await.unwrap();
    assert_eq!(elsewhere["status"]["phase"], "Pending");
    assert_eq!(elsewhere["spec"]["nodeName"], "other-node");
}

#[tokio::test]
async fn never_policy_pods_become_terminal_and_keep_transition_times() {
    let Started {
        kubelet,
        admin,
        runtime,
        ..
    } = start_pods(vec![one_shot_pod("ok"), one_shot_pod("bad")]).await;
    let uid = uid_of(&admin, "ok").await;
    let bad_uid = uid_of(&admin, "bad").await;
    let scheduled_before = condition(
        &admin.get_pod("default", "ok").await.unwrap(),
        "PodScheduled",
    )["lastTransitionTime"]
        .clone();

    runtime.set_container_exit(&uid, "hello", 0);
    runtime.set_container_exit(&bad_uid, "hello", 3);
    kubelet.reconcile_once().await.unwrap();

    let ok = admin.get_pod("default", "ok").await.unwrap();
    assert_eq!(phase(&ok), "Succeeded");
    let terminated = &ok["status"]["containerStatuses"][0]["state"]["terminated"];
    assert_eq!(terminated["exitCode"], 0);
    assert_eq!(terminated["reason"], "Completed");
    assert!(
        terminated["containerID"]
            .as_str()
            .is_some_and(|id| id.starts_with("mock://mock-c-")),
        "{terminated}"
    );
    assert_eq!(ok["status"]["containerStatuses"][0]["ready"], false);
    let ready = condition(&ok, "Ready");
    assert_eq!(ready["status"], "False");
    assert_eq!(ready["reason"], "PodCompleted");
    assert_eq!(
        condition(&ok, "PodScheduled")["lastTransitionTime"],
        scheduled_before
    );

    let bad = admin.get_pod("default", "bad").await.unwrap();
    assert_eq!(phase(&bad), "Failed");
    let terminated = &bad["status"]["containerStatuses"][0]["state"]["terminated"];
    assert_eq!(terminated["exitCode"], 3);
    assert_eq!(terminated["reason"], "Error");

    // Terminal pods are left alone: no restart, no new start, no status rewrite.
    let before = resource_version(&admin, "ok").await;
    kubelet.reconcile_once().await.unwrap();
    assert_eq!(before, resource_version(&admin, "ok").await);
    assert_eq!(runtime.container_ids(&uid).len(), 1);

    // A terminal pod is deleted at once by the apiserver; the kubelet then removes
    // its sandbox as an orphan.
    admin.delete_pod("default", "ok").await.unwrap();
    assert!(admin.get_pod("default", "ok").await.is_err());
    let report = kubelet.reconcile_once().await.unwrap();
    assert_eq!(report.orphans_stopped, 1);
    assert_eq!(runtime.sandbox_count(&uid), 0);
    assert_eq!(
        runtime.container_ids(&uid),
        <[std::string::String; 0]>::default()
    );
    assert_eq!(runtime.sandbox_count(&bad_uid), 1);
}

#[tokio::test]
async fn always_policy_restarts_with_crash_loop_back_off_and_keeps_previous_logs() {
    let Started {
        kubelet,
        admin,
        runtime,
        ..
    } = start_pods(vec![pod_with_policy("loop", "Always")]).await;
    let uid = uid_of(&admin, "loop").await;

    // First exit restarts at once as attempt 1; the pod stays Running.
    runtime.set_container_exit(&uid, "hello", 1);
    kubelet.reconcile_once().await.unwrap();
    let pod = admin.get_pod("default", "loop").await.unwrap();
    assert_eq!(phase(&pod), "Running");
    let status = &pod["status"]["containerStatuses"][0];
    assert_eq!(status["restartCount"], 1);
    assert!(status["state"]["running"].is_object());
    assert_eq!(status["lastState"]["terminated"]["exitCode"], 1);
    assert_eq!(
        runtime.container_ids(&uid).len(),
        2,
        "previous attempt is kept"
    );

    // The previous attempt's log is still readable.
    runtime.set_container_logs(format!("{uid}:hello"), "attempt log\n");
    let text = kubelet
        .log_source()
        .read_pod_log(
            &pod,
            &PodLogOptions {
                previous: true,
                ..PodLogOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(text, "attempt log\n");

    // A second exit inside the back-off window waits as CrashLoopBackOff.
    runtime.set_container_exit(&uid, "hello", 1);
    kubelet.reconcile_once().await.unwrap();
    let pod = admin.get_pod("default", "loop").await.unwrap();
    assert_eq!(phase(&pod), "Running");
    let status = &pod["status"]["containerStatuses"][0];
    assert_eq!(status["restartCount"], 1);
    assert_eq!(status["ready"], false);
    assert_eq!(status["state"]["waiting"]["reason"], "CrashLoopBackOff");
    let message = status["state"]["waiting"]["message"].as_str().unwrap();
    assert!(
        message.starts_with("back-off 10s restarting failed container=hello pod=loop_default("),
        "{message}"
    );
    assert_eq!(status["lastState"]["terminated"]["exitCode"], 1);
    let ready = condition(&pod, "Ready");
    assert_eq!(ready["status"], "False");
    assert_eq!(ready["reason"], "ContainersNotReady");
    assert_eq!(ready["message"], "containers with unready status: [hello]");
    assert_eq!(runtime.container_ids(&uid).len(), 2);

    // OnFailure treats a clean exit as completion.
    admin
        .create_pod("default", pod_with_policy("onfail", "OnFailure"))
        .await
        .unwrap();
    admin
        .bind_pod(
            "default",
            "onfail",
            json!({"target":{"kind":"Node","name":"test-node"}}),
        )
        .await
        .unwrap();
    kubelet.reconcile_once().await.unwrap();
    let onfail_uid = uid_of(&admin, "onfail").await;
    runtime.set_container_exit(&onfail_uid, "hello", 0);
    kubelet.reconcile_once().await.unwrap();
    assert_eq!(
        phase(&admin.get_pod("default", "onfail").await.unwrap()),
        "Succeeded"
    );
}

#[tokio::test]
async fn deleting_a_running_pod_stops_it_with_grace_then_removes_it() {
    let Started {
        kubelet,
        admin,
        runtime,
        ..
    } = start_pods(vec![pod_with_policy("web", "Always")]).await;
    let uid = uid_of(&admin, "web").await;

    // Graceful deletion marks the object instead of removing it.
    let marked = admin
        .delete_pod_options("default", "web", None)
        .await
        .unwrap()
        .expect("running pod is marked, not removed");
    assert!(marked["metadata"]["deletionTimestamp"].is_string());
    assert_eq!(marked["metadata"]["deletionGracePeriodSeconds"], 30);

    // First pass: StopContainer with the remaining grace runs in the background.
    kubelet.reconcile_once().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let stops = runtime.stop_calls();
    assert_eq!(stops.len(), 1, "{stops:?}");
    assert!((29..=30).contains(&stops[0].1), "{stops:?}");
    assert!(admin.get_pod("default", "web").await.is_ok());

    // Second pass: final status recorded, sandbox removed, object deleted; no restart
    // despite restartPolicy Always.
    let mut deleted = false;
    for _ in 0..20 {
        kubelet.reconcile_once().await.unwrap();
        if admin.get_pod("default", "web").await.is_err()
            && runtime.sandbox_count(&uid) == 0
            && runtime.container_ids(&uid).is_empty()
            && !runtime.is_pod_active(&uid)
        {
            deleted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(deleted, "Pod and sandbox should be fully deleted");

    // A second create of the same name works and gets a fresh uid and sandbox.
    admin
        .create_pod("default", pod_with_policy("web", "Always"))
        .await
        .unwrap();
    admin
        .bind_pod(
            "default",
            "web",
            json!({"target":{"kind":"Node","name":"test-node"}}),
        )
        .await
        .unwrap();
    kubelet.reconcile_once().await.unwrap();
    let again = admin.get_pod("default", "web").await.unwrap();
    assert_eq!(phase(&again), "Running");
    assert_ne!(again["metadata"]["uid"], uid);
}

#[tokio::test]
async fn log_reader_rejects_pods_that_are_not_running_here() {
    let dir = TempDir::new().unwrap();
    let (apiserver, options) = setup(&dir);
    let runtime = Arc::new(MockRuntimeProvider::new("mock"));
    let source = KubeletService::new(options, apiserver, runtime).log_source();
    let options = PodLogOptions::default();

    let unbound = one_shot_pod("unbound");
    let err = source.read_pod_log(&unbound, &options).await.unwrap_err();
    assert!(err.to_string().contains("not assigned"), "{err}");

    let mut waiting = one_shot_pod("waiting");
    waiting["metadata"]["uid"] = json!("uid-waiting");
    waiting["spec"]["nodeName"] = json!("test-node");
    waiting["status"] = json!({
        "containerStatuses": [{ "name": "hello", "state": { "waiting": { "reason": "ContainerCreating" } } }]
    });
    let err = source.read_pod_log(&waiting, &options).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("waiting to start: ContainerCreating"),
        "{err}"
    );
}

#[tokio::test]
async fn log_and_exec_sources_reject_companion_node_pods() {
    let dir = TempDir::new().unwrap();
    let (apiserver, options) = setup(&dir);
    let runtime = Arc::new(MockRuntimeProvider::new("mock"));
    let service = KubeletService::new(options, apiserver, runtime);
    let log_source = service.log_source();
    let exec_source = service.exec_source();

    let mut companion_pod = one_shot_pod("worker-pod");
    companion_pod["metadata"]["uid"] = json!("uid-companion");
    companion_pod["spec"]["nodeName"] = json!("test-node-worker");
    companion_pod["status"] = json!({
        "containerStatuses": [{ "name": "hello", "state": { "waiting": { "reason": "ContainerCreating" } } }]
    });

    let log_err = log_source
        .read_pod_log(&companion_pod, &PodLogOptions::default())
        .await
        .unwrap_err();
    assert!(
        log_err.to_string().contains("not assigned"),
        "expected node ownership rejection, got: {log_err}"
    );

    assert!(
        exec_source
            .exec_in_pod(&companion_pod, "hello", &["ls".into()])
            .await
            .unwrap_err()
            .to_string()
            .contains("not assigned")
    );
    let mut other_pod = companion_pod.clone();
    other_pod["spec"]["nodeName"] = json!("other-node");
    let other_log_err = log_source
        .read_pod_log(&other_pod, &PodLogOptions::default())
        .await
        .unwrap_err();
    assert!(
        other_log_err.to_string().contains("not assigned"),
        "{other_log_err}"
    );

    let other_exec_err = exec_source
        .exec_in_pod(&other_pod, "hello", &["ls".to_string()])
        .await
        .unwrap_err();
    assert!(
        other_exec_err.to_string().contains("not assigned"),
        "{other_exec_err}"
    );
}

#[tokio::test]
async fn containerd_cri_observed_runtime_live_or_skip() {
    if !cfg!(target_os = "linux") {
        println!("SKIPPING containerd CRI test: target OS is not Linux");
        return;
    }
    let socket = std::env::var("CONTAINERD_SOCKET").map_or_else(
        |_| std::path::PathBuf::from("/run/containerd/containerd.sock"),
        std::path::PathBuf::from,
    );
    if !socket.exists() {
        println!(
            "SKIPPING containerd CRI test: socket not available at {}",
            socket.display()
        );
        return;
    }
    let runtime = Arc::new(CriRuntimeProvider::new(&socket));
    if let Err(err) = runtime.check_available().await {
        println!(
            "SKIPPING containerd CRI test: containerd check_available ping failed at {}: {err}",
            socket.display()
        );
        return;
    }

    let dir = TempDir::new().unwrap();
    let (apiserver, options) = setup(&dir);
    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let kubelet = KubeletService::new(options, apiserver.clone(), runtime.clone());
    kubelet.start().await.unwrap();
    let admin = apiserver.admin_client();

    let pod_json = one_shot_pod("live-cri-test");
    admin.create_pod("default", pod_json).await.unwrap();

    let report = kubelet.reconcile_once().await.unwrap();
    assert_eq!(report.bound, 1);
    assert_eq!(report.failed, 0);

    let pod = admin.get_pod("default", "live-cri-test").await.unwrap();
    assert_eq!(pod["spec"]["nodeName"], "test-node");

    // Clean up
    let _ = admin
        .delete_pod_options("default", "live-cri-test", Some(0))
        .await;
    for _ in 0..20 {
        let _ = kubelet.reconcile_once().await;
        if admin.get_pod("default", "live-cri-test").await.is_err() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
