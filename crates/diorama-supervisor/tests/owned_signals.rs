#![cfg(any(target_os = "linux", target_os = "macos"))]
use diorama_supervisor::process::{ExternalServiceAdapter, OwnedProcessAdapter, ProcessCommand};
use diorama_supervisor::signals::{ShutdownSignal, run_with_signals};
use diorama_supervisor::{
    AdapterError, ComponentKind, ComponentSpec, ComponentState, FailurePolicy, Registration,
    StopCause, Supervisor, stop_channel,
};
use rustix::process::{Signal, getpid, kill_process};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

struct StartupGate(Arc<AtomicBool>);
impl diorama_supervisor::Adapter for StartupGate {
    fn run(
        self: Box<Self>,
        _: diorama_supervisor::AdapterContext,
    ) -> diorama_supervisor::AdapterFuture {
        Box::pin(async move {
            self.0.store(true, Ordering::SeqCst);
            Ok(())
        })
    }
}
async fn gate_ready(gate: &AtomicBool) {
    tokio::time::timeout(Duration::from_secs(4), async {
        while !gate.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("coordinator admitted dependent readiness");
}

fn spec(id: &str) -> ComponentSpec {
    ComponentSpec {
        id: id.into(),
        prerequisites: vec![],
        kind: ComponentKind::LongRunning,
        failure_policy: FailurePolicy::Fatal,
        startup_timeout: Duration::from_secs(5),
    }
}
fn command(mode: &str, path: &Path) -> ProcessCommand {
    ProcessCommand::new("/fixture")
        .arg("process-child")
        .arg(mode)
        .arg(path)
        .env_clear()
        .env("diorama_SIGNAL_DISPOSABLE", "1")
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
}
async fn ready(path: PathBuf) -> Result<(), AdapterError> {
    loop {
        if path.join("ready").is_file() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn bounded_ready(path: &Path) {
    tokio::time::timeout(Duration::from_secs(4), ready(path.to_owned()))
        .await
        .expect("fixture readiness deadline")
        .expect("fixture readiness");
}

async fn mixed_signals(first: Signal) {
    kill_process(getpid(), first).expect("deliver actual signal");
    // A second, mixed delivery cannot reset the shutdown budget. The bridge
    // may already finish for fast children; permanent installed handlers remain.
    tokio::time::sleep(Duration::from_millis(5)).await;
    kill_process(
        getpid(),
        if first == Signal::INT {
            Signal::TERM
        } else {
            Signal::INT
        },
    )
    .expect("repeat signal");
}

fn check_report(report: &diorama_supervisor::signals::SignalRunReport, mode: &str, first: Signal) {
    let fatal = mode == "fatal";
    assert!(report.listener_closed.is_none());
    if fatal {
        assert!(report.first_signal.is_none());
        let expected = diorama_supervisor::ComponentFailure {
            component: "owned".into(),
            kind: diorama_supervisor::FailureKind::Adapter("fixture_worker_failure"),
        };
        assert_eq!(report.supervisor.cause, StopCause::Fatal(expected.clone()));
        assert!(report.supervisor.failures.contains(&expected));
    } else {
        assert_eq!(report.supervisor.cause, StopCause::Requested);
        assert_eq!(
            report.first_signal,
            Some(if first == Signal::INT {
                ShutdownSignal::Interrupt
            } else {
                ShutdownSignal::Terminate
            })
        );
        assert_eq!(report.supervisor.failures, []);
    }
    let expected_cleanup = if mode == "force" {
        vec![diorama_supervisor::CleanupFailure {
            component: "owned".into(),
            kind: diorama_supervisor::CleanupKind::Forced,
        }]
    } else {
        vec![]
    };
    assert_eq!(report.supervisor.cleanup_failures, expected_cleanup);
}

async fn case(base: &Path, iteration: usize, mode: &str) {
    let path = base.join(format!("{iteration}-{mode}"));
    let probe_path = path.clone();
    let partial = mode == "partial";
    let fatal = mode == "fatal";
    let (adapter, observer) = OwnedProcessAdapter::new(
        command(if mode == "force" { "ignore" } else { "steady" }, &path),
        async move {
            ready(probe_path).await?;
            if fatal {
                return Err(AdapterError {
                    code: "fixture_worker_failure",
                });
            }
            if partial {
                std::future::pending::<()>().await;
            }
            Ok(())
        },
    );
    let mut dependent = spec("dependent");
    dependent.prerequisites.push("owned".into());
    let (dependent_adapter, dependent_observer) = OwnedProcessAdapter::new(
        command("steady", &path.join("dependent")),
        ready(path.join("dependent")),
    );
    let admitted = Arc::new(AtomicBool::new(false));
    let mut gate = spec("startup-gate");
    gate.kind = ComponentKind::OneShot;
    gate.prerequisites.push("dependent".into());
    let supervisor = Supervisor::new(vec![
        Registration::new(gate, StartupGate(admitted.clone())),
        Registration::new(spec("owned"), adapter),
        Registration::new(dependent, dependent_adapter),
    ])
    .expect("graph");
    let task = tokio::spawn(run_with_signals(supervisor));
    bounded_ready(&path).await;
    if !partial && !fatal {
        gate_ready(&admitted).await;
    }
    let started = Instant::now();
    let first = if iteration.is_multiple_of(2) {
        Signal::INT
    } else {
        Signal::TERM
    };
    if !fatal {
        mixed_signals(first).await;
    }
    let report = tokio::time::timeout(Duration::from_secs(38), task)
        .await
        .expect("bounded supervisor observation")
        .expect("join bridge")
        .expect("signal installation");
    check_report(&report, mode, first);
    assert_eq!(admitted.load(Ordering::SeqCst), !partial && !fatal);
    if !partial && !fatal {
        for id in ["owned", "dependent"] {
            assert!(
                report
                    .supervisor
                    .transitions
                    .iter()
                    .any(|event| event.component == id && event.state == ComponentState::Ready)
            );
        }
    }

    let snapshot = observer.wait(Duration::from_secs(2)).await;
    assert!(
        snapshot.complete() && snapshot.leader_reaped && snapshot.thread_joined,
        "{snapshot:?}"
    );
    let child = dependent_observer.wait(Duration::from_secs(2)).await;
    if partial || fatal {
        assert!(!child.started && !child.spawned);
        assert!(
            !report
                .supervisor
                .transitions
                .iter()
                .any(|event| event.component == "owned" && event.state == ComponentState::Ready)
        );
    } else {
        assert!(child.complete() && child.leader_reaped);
    }
    if mode == "force" {
        assert!(started.elapsed() >= Duration::from_secs(29));
        assert!(started.elapsed() < Duration::from_secs(38));
        assert!(snapshot.force_requested && snapshot.term_attempted);
        assert_eq!(snapshot.exit.expect("exit").signal, Some(9));
    } else if !fatal {
        assert_eq!(snapshot.exit.expect("exit").code, Some(0));
    }
    println!(
        "diorama_OWNED_SIGNAL case={mode} iteration={iteration} leader_reaped=true owner_joined=true dependent_started={} elapsed_ms={}",
        child.started,
        started.elapsed().as_millis()
    );
}

#[tokio::test]
#[ignore = "requires disposable supervisor-signals driver; installs permanent process handlers"]
async fn disposable_owned_signals() {
    assert_eq!(
        std::env::var("diorama_SIGNAL_DISPOSABLE").as_deref(),
        Ok("1")
    );
    let base = PathBuf::from("/tmp/owned-signals");
    let sentinel_path = base.join("sentinel");
    let (sentinel, observer) = OwnedProcessAdapter::new(
        command("steady", &sentinel_path),
        ready(sentinel_path.clone()),
    );
    let (stop, receiver) = stop_channel();
    let sentinel_task = tokio::spawn(
        Supervisor::new(vec![Registration::new(spec("sentinel"), sentinel)])
            .expect("sentinel graph")
            .run(receiver),
    );
    bounded_ready(&sentinel_path).await;
    for iteration in 0..20 {
        for mode in ["full", "partial", "fatal"] {
            case(&base, iteration, mode).await;
        }
    }
    case(&base, 20, "force").await;
    let before = std::fs::read_to_string(sentinel_path.join("heartbeat")).expect("heartbeat");
    let (external_stop, external_receiver) = stop_channel();
    let external = Supervisor::new(vec![Registration::new(
        spec("external"),
        ExternalServiceAdapter::new(async { Ok(()) }),
    )])
    .expect("external graph");
    let external_task = tokio::spawn(external.run(external_receiver));
    tokio::time::sleep(Duration::from_millis(50)).await;
    external_stop.stop();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), external_task)
            .await
            .expect("external stop deadline")
            .expect("external join")
            .cleanup_failures,
        []
    );
    assert_ne!(
        before,
        std::fs::read_to_string(sentinel_path.join("heartbeat")).expect("surviving heartbeat")
    );
    assert!(!observer.snapshot().leader_reaped);
    stop.stop();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), sentinel_task)
            .await
            .expect("sentinel stop deadline")
            .expect("sentinel join")
            .cleanup_failures,
        []
    );
    assert!(observer.wait(Duration::from_secs(2)).await.complete());
    println!(
        "diorama_OWNED_QUALIFICATION repetitions=20 combined_cases=61 sentinel_survived=true all_owners_joined=true"
    );
}
