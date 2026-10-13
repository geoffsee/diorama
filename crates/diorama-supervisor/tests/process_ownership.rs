#![cfg(any(target_os = "linux", target_os = "macos"))]
use diorama_supervisor::process::{
    ExternalServiceAdapter, OwnedProcessAdapter, ProcessCleanup, ProcessCleanupSnapshot,
    ProcessCommand,
};
use diorama_supervisor::{
    AdapterError, ComponentKind, ComponentSpec, ComponentState, FailureKind, FailurePolicy,
    Registration, Supervisor, stop_channel,
};
use std::future::pending;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[test]
fn constructor_and_rejected_graph_have_no_process_or_probe_effects() {
    let polled = Arc::new(AtomicBool::new(false));
    let flag = polled.clone();
    let (adapter, cleanup) =
        OwnedProcessAdapter::new(ProcessCommand::new("must-never-execute"), async move {
            flag.store(true, Ordering::SeqCst);
            Ok(())
        });
    assert_eq!(cleanup.snapshot(), ProcessCleanupSnapshot::default());
    let mut invalid = spec("invalid");
    invalid.prerequisites.push("missing".into());
    assert!(Supervisor::new(vec![Registration::new(invalid, adapter)]).is_err());
    assert!(!polled.load(Ordering::SeqCst));
    assert_eq!(cleanup.snapshot(), ProcessCleanupSnapshot::default());
}
#[test]
fn command_and_adapter_debug_exclude_credentials() {
    let command = ProcessCommand::new("private-program")
        .arg("private-argument")
        .env("PRIVATE", "private-value");
    assert_eq!(format!("{command:?}"), "ProcessCommand(<private command>)");
    let (adapter, _) = OwnedProcessAdapter::new(command, pending());
    let debug = format!("{adapter:?}");
    for secret in ["private-program", "private-argument", "private-value"] {
        assert!(!debug.contains(secret));
    }
}
fn spec(id: &str) -> ComponentSpec {
    ComponentSpec {
        id: id.into(),
        prerequisites: vec![],
        kind: ComponentKind::LongRunning,
        failure_policy: FailurePolicy::Fatal,
        startup_timeout: Duration::from_secs(4),
    }
}
fn command(mode: &str, root: &Path) -> ProcessCommand {
    ProcessCommand::new("/fixture")
        .arg("process-child")
        .arg(mode)
        .arg(root)
        .env_clear()
        .env("diorama_PROCESS_DISPOSABLE", "1")
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
}
async fn ready(root: PathBuf) -> Result<(), AdapterError> {
    loop {
        if root.join("ready").is_file() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn cleanup(observer: &ProcessCleanup) -> ProcessCleanupSnapshot {
    let snapshot = observer.wait(Duration::from_secs(3)).await;
    assert!(snapshot.complete(), "cleanup incomplete: {snapshot:?}");
    assert!(
        snapshot.spawned
            && snapshot.leader_reaped
            && snapshot.thread_finished
            && snapshot.thread_joined
    );
    assert!(!snapshot.ownership_lost);
    snapshot
}
fn emit(name: &str, snapshot: &ProcessCleanupSnapshot, elapsed: u128) {
    println!(
        "diorama_PROCESS {{\"case\":\"{name}\",\"spawned\":{},\"term_attempted\":{},\"kill_attempted\":{},\"leader_reaped\":{},\"thread_joined\":{},\"complete\":{},\"exit_code\":{},\"signal\":{},\"elapsed_ms\":{elapsed},\"error\":{}}}",
        snapshot.spawned,
        snapshot.term_attempted,
        snapshot.kill_attempted,
        snapshot.leader_reaped,
        snapshot.thread_joined,
        snapshot.complete(),
        snapshot
            .exit
            .and_then(|exit| exit.code)
            .map_or_else(|| "null".into(), |v| v.to_string()),
        snapshot
            .exit
            .and_then(|exit| exit.signal)
            .map_or_else(|| "null".into(), |v| v.to_string()),
        snapshot
            .error
            .map_or_else(|| "null".into(), |code| format!("\"{code}\""))
    );
}
async fn orderly(mode: &str, base: &Path) {
    let root = base.join(mode);
    let launched = Instant::now();
    let (adapter, observer) = OwnedProcessAdapter::new(command(mode, &root), ready(root.clone()));
    let supervisor =
        Supervisor::new(vec![Registration::new(spec(mode), adapter)]).expect("valid graph");
    let (stop, receiver) = stop_channel();
    let task = tokio::spawn(supervisor.run(receiver));
    tokio::time::timeout(Duration::from_secs(3), ready(root.clone()))
        .await
        .expect("fixture ready")
        .expect("readiness");
    if mode == "delayed" {
        assert!(launched.elapsed() >= Duration::from_millis(150));
    }
    tokio::time::sleep(Duration::from_millis(40)).await;
    let start = Instant::now();
    stop.stop();
    let report = tokio::time::timeout(Duration::from_secs(37), task)
        .await
        .expect("supervisor deadline")
        .expect("join supervisor");
    assert!(report.failures.is_empty(), "{report:?}");
    if mode == "term-error" {
        assert_eq!(report.cause, diorama_supervisor::StopCause::Requested);
        assert!(report.cleanup_failures.iter().any(|failure| matches!(
            failure.kind,
            diorama_supervisor::CleanupKind::Adapter("process_exited_unsuccessfully")
        )));
    }
    assert!(
        report
            .transitions
            .iter()
            .any(|event| event.state == ComponentState::Ready)
    );
    let snapshot = cleanup(&observer).await;
    assert!(snapshot.term_attempted && snapshot.kill_attempted);
    if mode == "ignore" {
        assert!(start.elapsed() >= Duration::from_secs(29));
        assert_eq!(snapshot.exit.expect("exit").signal, Some(9));
        assert!(root.join("term").exists());
    } else {
        assert_eq!(
            snapshot.exit.expect("exit").code,
            Some(if mode == "term-error" { 17 } else { 0 })
        );
        assert_eq!(
            std::fs::read_to_string(root.join("stopped")).expect("termination marker"),
            "graceful"
        );
    }
    if mode == "family" {
        assert_eq!(
            std::fs::read_to_string(root.join("descendant_reaped")).expect("descendant wait"),
            "0"
        );
        assert!(root.join("child/stopped").exists());
    }
    emit(mode, &snapshot, start.elapsed().as_millis());
}

/// All subprocess scenarios run under the external Docker driver's PID namespace and deadlines.
#[tokio::test]
#[ignore = "requires tools/supervisor-process disposable Linux driver"]
async fn disposable_process_cases() {
    assert_eq!(
        std::env::var("diorama_PROCESS_DISPOSABLE").as_deref(),
        Ok("1")
    );
    let base = Path::new("/tmp/process-cases");
    std::fs::create_dir_all(base).expect("private fixture directory");
    let sentinel = base.join("sentinel");
    let (adapter, sentinel_observer) =
        OwnedProcessAdapter::new(command("sentinel", &sentinel), ready(sentinel.clone()));
    let (sentinel_stop, receiver) = stop_channel();
    let sentinel_task = tokio::spawn(
        Supervisor::new(vec![Registration::new(spec("sentinel"), adapter)])
            .expect("sentinel graph")
            .run(receiver),
    );
    tokio::time::timeout(Duration::from_secs(3), ready(sentinel.clone()))
        .await
        .expect("sentinel ready")
        .expect("readiness");
    for mode in ["delayed", "family", "ignore", "term-error"] {
        orderly(mode, base).await;
    }
    failure_cases(base).await;
    for mode in ["spawn-error", "startup-timeout"] {
        startup_failure_case(mode, base).await;
    }
    let (stop, receiver) = stop_channel();
    let task = tokio::spawn(
        Supervisor::new(vec![Registration::new(
            spec("external"),
            ExternalServiceAdapter::new(async { Ok(()) }),
        )])
        .expect("external graph")
        .run(receiver),
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    stop.stop();
    assert_eq!(task.await.expect("external join").failures, []);
    let before = std::fs::read_to_string(sentinel.join("heartbeat")).expect("sentinel heartbeat");
    tokio::time::sleep(Duration::from_millis(80)).await;
    let after =
        std::fs::read_to_string(sentinel.join("heartbeat")).expect("sentinel heartbeat advanced");
    assert_ne!(before, after, "unrelated external process must remain live");
    sentinel_stop.stop();
    sentinel_task.await.expect("sentinel shutdown");
    let snapshot = cleanup(&sentinel_observer).await;
    emit("sentinel-survived-external-stop", &snapshot, 0);
}

async fn failure_cases(base: &Path) {
    for mode in [
        "early",
        "leader-exits-first",
        "oneshot",
        "probe-error",
        "worker-panic",
        "cancelled",
    ] {
        let root = base.join(mode);
        let future_root = root.clone();
        let readiness = async move {
            if matches!(mode, "early" | "leader-exits-first" | "oneshot") {
                return pending().await;
            }
            ready(future_root).await?;
            assert!(mode != "worker-panic", "synthetic adapter worker failure");
            if mode == "probe-error" {
                return Err(AdapterError {
                    code: "synthetic_probe_failure",
                });
            }
            Ok(())
        };
        let fixture_mode = if matches!(mode, "early" | "leader-exits-first" | "oneshot") {
            mode
        } else {
            "steady"
        };
        let (adapter, observer) = OwnedProcessAdapter::new(command(fixture_mode, &root), readiness);
        let mut specification = spec(mode);
        if mode == "oneshot" {
            specification.kind = ComponentKind::OneShot;
        }
        let (stop, receiver) = stop_channel();
        let task = tokio::spawn(
            Supervisor::new(vec![Registration::new(specification, adapter)])
                .expect("graph")
                .run(receiver),
        );
        if mode == "cancelled" {
            tokio::time::timeout(Duration::from_secs(3), ready(root))
                .await
                .expect("cancel fixture ready")
                .expect("readiness");
            task.abort();
            assert!(task.await.expect_err("cancelled supervisor").is_cancelled());
        } else {
            let report = tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .expect("case bounded")
                .expect("supervisor join");
            if mode == "oneshot" {
                assert_eq!(report.failures, []);
            } else {
                assert_ne!(report.failures, []);
            }
            if matches!(mode, "early" | "leader-exits-first") {
                assert!(
                    !report
                        .transitions
                        .iter()
                        .any(|event| event.state == ComponentState::Ready)
                );
            }
            if mode == "worker-panic" {
                assert!(
                    report
                        .failures
                        .iter()
                        .any(|failure| failure.kind == FailureKind::Panic)
                );
            }
        }
        drop(stop);
        let snapshot = cleanup(&observer).await;
        assert!(snapshot.kill_attempted);
        if matches!(mode, "early" | "leader-exits-first") {
            assert_eq!(snapshot.exit.expect("early status").code, Some(17));
        }
        emit(mode, &snapshot, 0);
    }
}

async fn startup_failure_case(mode: &str, base: &Path) {
    let root = base.join(mode);
    let provider_root = root.join("provider");
    let (provider, provider_cleanup) = OwnedProcessAdapter::new(
        command("steady", &provider_root),
        ready(provider_root.clone()),
    );
    let readiness_polled = Arc::new(AtomicBool::new(false));
    let polled = readiness_polled.clone();
    let target_root = root.join("target");
    let probe_root = target_root.clone();
    let command = if mode == "spawn-error" {
        ProcessCommand::new(root.join("absent-executable"))
    } else {
        command("steady", &target_root)
    };
    let (target, target_cleanup) = OwnedProcessAdapter::new(command, async move {
        polled.store(true, Ordering::SeqCst);
        ready(probe_root).await?;
        pending().await
    });
    let mut target_spec = spec(mode);
    target_spec.prerequisites.push("provider".into());
    target_spec.startup_timeout = Duration::from_secs(1);
    let (dependent, dependent_cleanup) = OwnedProcessAdapter::new(
        ProcessCommand::new(root.join("dependent-must-not-execute")),
        pending(),
    );
    let mut dependent_spec = spec("dependent");
    dependent_spec.prerequisites.push(mode.into());
    let supervisor = Supervisor::new(vec![
        Registration::new(spec("provider"), provider),
        Registration::new(target_spec, target),
        Registration::new(dependent_spec, dependent),
    ])
    .expect("partial startup graph");
    let (_stop, receiver) = stop_channel();
    let began = Instant::now();
    let report = tokio::time::timeout(Duration::from_secs(5), supervisor.run(receiver))
        .await
        .expect("bounded startup failure");
    let expected = diorama_supervisor::ComponentFailure {
        component: mode.into(),
        kind: if mode == "spawn-error" {
            FailureKind::Adapter("process_spawn_failed")
        } else {
            FailureKind::StartupTimeout
        },
    };
    let expected_cause = diorama_supervisor::StopCause::Fatal(expected.clone());
    assert_eq!(report.cause, expected_cause);
    assert!(report.failures.contains(&expected));
    assert!(report.cleanup_failures.is_empty(), "{report:?}");
    assert!(
        !report
            .transitions
            .iter()
            .any(|event| event.component == "dependent" && event.state == ComponentState::Starting)
    );
    assert!(!dependent_cleanup.snapshot().started);
    let provider = cleanup(&provider_cleanup).await;
    assert_eq!(provider.exit.expect("provider exit").code, Some(0));
    assert!(provider_root.join("stopped").is_file());
    let target = target_cleanup.wait(Duration::from_secs(2)).await;
    assert!(
        target.started && target.thread_finished && target.thread_joined && !target.ownership_lost
    );
    if mode == "spawn-error" {
        assert!(!readiness_polled.load(Ordering::SeqCst));
        assert!(
            !target.spawned
                && !target.leader_reaped
                && !target.term_attempted
                && !target.kill_attempted
        );
        assert!(!target.complete());
        assert_eq!(target.error, Some("process_spawn_failed"));
        assert_eq!(target.exit, None);
        emit(mode, &target, 0);
    } else {
        assert!(readiness_polled.load(Ordering::SeqCst));
        assert!(target_root.join("ready").is_file());
        assert!(
            !report
                .transitions
                .iter()
                .any(|event| event.component == mode && event.state == ComponentState::Ready)
        );
        assert!(
            target.complete()
                && target.leader_reaped
                && target.term_attempted
                && target.kill_attempted
        );
        assert_eq!(target.exit.expect("target exit").code, Some(0));
        assert!(began.elapsed() >= Duration::from_secs(1));
        emit(mode, &target, began.elapsed().as_millis());
    }
}
