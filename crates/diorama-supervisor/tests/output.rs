#![cfg(any(target_os = "linux", target_os = "macos"))]
use diorama_supervisor::process::{
    OutputLimit, OutputSnapshot, OwnedProcessAdapter, ProcessCommand,
};
#[test]
fn capture_constructor_is_effect_free_and_command_debug_private() {
    let (adapter, cleanup, output) = OwnedProcessAdapter::new_with_bounded_output(
        ProcessCommand::new("private-program").arg("private-value"),
        std::future::pending(),
        OutputLimit::new(4096).unwrap(),
    );
    assert!(!cleanup.snapshot().started);
    assert_eq!(output.snapshot(), OutputSnapshot::NotStarted);
    for diagnostic in [format!("{adapter:?}"), format!("{output:?}")] {
        assert!(!diagnostic.contains("private-program"));
        assert!(!diagnostic.contains("private-value"));
    }
    drop(adapter);
    assert_eq!(output.snapshot(), OutputSnapshot::NotStarted);
}

use diorama_supervisor::process::{OutputStatus, ProcessCleanupSnapshot};
use diorama_supervisor::{
    AdapterError, ComponentKind, ComponentSpec, FailurePolicy, Registration, Supervisor,
    stop_channel,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};

async fn ready(root: PathBuf) -> Result<(), AdapterError> {
    while !root.join("ready").exists() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}
fn assert_retired(cleanup: &ProcessCleanupSnapshot) {
    assert!(cleanup.thread_joined && cleanup.thread_finished);
    assert!(!cleanup.ownership_lost);
    assert!(!cleanup.spawned || cleanup.leader_reaped);
}
fn assert_capture(mode: &str, captured: &diorama_supervisor::process::CapturedOutput) {
    let expected = match mode {
        "overflow" | "flood" => OutputStatus::LimitExceeded,
        "missing" => OutputStatus::SpawnFailed,
        "stop" | "timeout" | "abort" | "probe-failure" => OutputStatus::Cancelled,
        "escaped" => OutputStatus::IncompleteAfterExit,
        _ => OutputStatus::Complete,
    };
    assert_eq!(captured.status, expected, "{mode}");
    assert!(captured.bytes().len() <= if mode == "simultaneous" { 2000 } else { 64 });
    match mode {
        "merged" => assert_eq!(captured.bytes(), b"out\xfferr\x00"),
        "empty" | "missing" => assert!(captured.bytes().is_empty()),
        "exact" | "overflow" | "flood" => assert_eq!(captured.bytes(), &[b'x'; 64]),
        "simultaneous" => {
            let mut sorted = captured.bytes().to_vec();
            sorted.sort_unstable();
            assert_eq!(sorted, [vec![b'a'; 1000], vec![b'b'; 1000]].concat());
        },
        "descendant" | "escaped" => assert_eq!(captured.bytes(), b"leader"),
        _ => {},
    }
}
fn fixture_command(mode: &str, root: &std::path::Path) -> ProcessCommand {
    if mode == "missing" {
        ProcessCommand::new("/missing-output-fixture")
    } else {
        ProcessCommand::new("/fixture")
            .arg("output-child")
            .arg(mode)
            .arg(root)
    }
}
fn assert_report(mode: &str, report: &diorama_supervisor::SupervisorReport) {
    use diorama_supervisor::{ComponentFailure, FailureKind, StopCause};
    let failure = match mode {
        "overflow" | "flood" => Some(FailureKind::Adapter("process_output_limit")),
        "missing" => Some(FailureKind::Adapter("process_spawn_failed")),
        "escaped" => Some(FailureKind::Adapter("process_output_incomplete")),
        "probe-failure" => Some(FailureKind::Adapter("fixture_readiness")),
        "timeout" => Some(FailureKind::StartupTimeout),
        _ => None,
    };
    if let Some(kind) = failure {
        let expected = ComponentFailure {
            component: mode.into(),
            kind,
        };
        assert_eq!(report.cause, StopCause::Fatal(expected.clone()));
        assert_eq!(report.failures, vec![expected]);
    } else {
        assert_eq!(
            report.cause,
            if mode == "stop" {
                StopCause::Requested
            } else {
                StopCause::Finished
            }
        );
        assert!(
            report.failures.is_empty() && report.cleanup_failures.is_empty(),
            "{report:?}"
        );
    }
}
async fn case(mode: &str, index: usize) {
    let root = PathBuf::from(format!("/tmp/output-{index}"));
    std::fs::create_dir(&root).unwrap();
    let command = fixture_command(mode, &root);
    let readiness_root = root.clone();
    let readiness_mode = mode.to_owned();
    let (adapter, cleanup, output) = OwnedProcessAdapter::new_with_bounded_output(
        command,
        async move {
            if matches!(readiness_mode.as_str(), "timeout" | "probe-failure") {
                ready(readiness_root).await?;
                if readiness_mode == "probe-failure" {
                    return Err(AdapterError {
                        code: "fixture_readiness",
                    });
                }
                return std::future::pending().await;
            }
            Ok(())
        },
        OutputLimit::new(if mode == "simultaneous" { 2000 } else { 64 }).unwrap(),
    );
    let spec = ComponentSpec {
        id: mode.into(),
        prerequisites: vec![],
        kind: ComponentKind::OneShot,
        failure_policy: FailurePolicy::Fatal,
        startup_timeout: Duration::from_millis(if mode == "timeout" { 200 } else { 3000 }),
    };
    let supervisor = Supervisor::new(vec![Registration::new(spec, adapter)]).unwrap();
    let (stop, receiver) = stop_channel();
    let began = Instant::now();
    let task = tokio::spawn(supervisor.run(receiver));
    if matches!(mode, "stop" | "abort") {
        tokio::time::timeout(Duration::from_secs(2), ready(root.clone()))
            .await
            .unwrap()
            .unwrap();
        if mode == "stop" {
            stop.stop();
        } else {
            task.abort();
        }
    }
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap();
    if mode == "abort" {
        assert!(result.unwrap_err().is_cancelled());
    } else {
        let report = result.unwrap();
        assert_report(mode, &report);
    }
    let retired = cleanup.wait(Duration::from_secs(2)).await;
    assert_retired(&retired);
    let OutputSnapshot::Finished(captured) = output.snapshot() else {
        panic!("terminal output");
    };
    assert_capture(mode, &captured);
    if mode == "stop" {
        assert_eq!(retired.exit.unwrap().code, Some(0));
        assert_eq!(std::fs::read(root.join("term")).unwrap(), b"handled");
    }
    if matches!(mode, "overflow" | "flood") {
        assert!(retired.kill_attempted);
        if mode == "flood" {
            assert!(retired.force_requested);
        }
    }
    println!(
        "diorama_OUTPUT case={mode} status={:?} bytes={} reaped={} joined={} elapsed_ms={}",
        captured.status,
        captured.bytes().len(),
        retired.leader_reaped,
        retired.thread_joined,
        began.elapsed().as_millis()
    );
    if mode == "escaped" {
        // The adapter does not own escaped sessions. Let this finite fixture exit; init reaps it.
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
#[tokio::test]
#[ignore = "adverse children require owned disposable PID namespace"]
async fn disposable_output_cases() {
    assert_eq!(
        std::env::var("diorama_OUTPUT_DISPOSABLE").as_deref(),
        Ok("1")
    );
    for (index, mode) in [
        "merged",
        "empty",
        "exact",
        "overflow",
        "simultaneous",
        "flood",
        "missing",
        "stop",
        "timeout",
        "abort",
        "probe-failure",
        "descendant",
        "escaped",
    ]
    .iter()
    .enumerate()
    {
        case(mode, index).await;
    }
    println!("diorama_OUTPUT_COMPLETE cases=13");
}
