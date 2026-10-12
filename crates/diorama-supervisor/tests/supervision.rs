use diorama_supervisor::*;
use std::future::{Future, pending};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::{Instant, sleep};

struct FunctionAdapter<F>(F);
impl<F, Fut> Adapter for FunctionAdapter<F>
where
    F: FnOnce(AdapterContext) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), AdapterError>> + Send + 'static,
{
    fn run(self: Box<Self>, context: AdapterContext) -> AdapterFuture {
        Box::pin(self.0(context))
    }
}
fn component<F, Fut>(
    id: &str,
    deps: &[&str],
    kind: ComponentKind,
    policy: FailurePolicy,
    seconds: u64,
    run: F,
) -> Registration
where
    F: FnOnce(AdapterContext) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), AdapterError>> + Send + 'static,
{
    Registration::new(
        ComponentSpec {
            id: id.into(),
            prerequisites: deps.iter().map(|id| (*id).into()).collect(),
            kind,
            failure_policy: policy,
            startup_timeout: Duration::from_secs(seconds),
        },
        FunctionAdapter(run),
    )
}
async fn cooperative(mut context: AdapterContext) -> Result<(), AdapterError> {
    context.ready();
    while context.stop_phase() == StopPhase::Running {
        context.changed().await;
    }
    Ok(())
}
const LONG: ComponentKind = ComponentKind::LongRunning;
const ONCE: ComponentKind = ComponentKind::OneShot;
const FATAL: FailurePolicy = FailurePolicy::Fatal;
const OPTIONAL: FailurePolicy = FailurePolicy::Degrade;

#[test]
fn rejects_invalid_graphs_before_adapter_effects() {
    for case in 0..6 {
        let effects = Arc::new(Mutex::new(0));
        let make = |id: &str, deps: &[&str], timeout| {
            let effects = effects.clone();
            component(id, deps, LONG, FATAL, timeout, move |_| async move {
                *effects.lock().unwrap() += 1;
                Ok(())
            })
        };
        let registrations = match case {
            0 => vec![make("a", &[], 1), make("a", &[], 1)],
            1 => vec![make("a", &["missing"], 1)],
            2 => vec![make("a", &["b"], 1), make("b", &["a"], 1)],
            3 => vec![make("a", &["a"], 1)],
            4 => vec![make("a", &[], 0)],
            _ => vec![make("a", &[], 1), make("b", &["a", "a"], 1)],
        };
        assert!(Supervisor::new(registrations).is_err());
        assert_eq!(*effects.lock().unwrap(), 0);
    }
}
#[tokio::test(start_paused = true)]
async fn dependencies_wait_for_usable_readiness_and_timeout_starts_at_launch() {
    let (stop, receiver) = stop_channel();
    let observations = Arc::new(Mutex::new(Vec::new()));
    let epoch = Instant::now();
    let observed = observations.clone();
    let provider = component(
        "provider",
        &[],
        LONG,
        FATAL,
        20,
        move |context| async move {
            sleep(Duration::from_secs(10)).await;
            cooperative(context).await
        },
    );
    let dependent = component(
        "dependent",
        &["provider"],
        LONG,
        FATAL,
        1,
        move |mut context| async move {
            observed.lock().unwrap().push(epoch.elapsed());
            sleep(Duration::from_millis(500)).await;
            context.ready();
            sleep(Duration::from_millis(100)).await;
            stop.stop();
            while context.stop_phase() == StopPhase::Running {
                context.changed().await;
            }
            Ok(())
        },
    );
    let report = Supervisor::new(vec![dependent, provider])
        .unwrap()
        .run(receiver)
        .await;
    assert_eq!(*observations.lock().unwrap(), [Duration::from_secs(10)]);
    assert!(report.failures.is_empty());
    assert!(report.cleanup_failures.is_empty());
    assert_eq!(report.cause, StopCause::Requested);
}
#[tokio::test(start_paused = true)]
async fn one_shot_readiness_does_not_release_dependencies_before_completion() {
    let (_stop, receiver) = stop_channel();
    let epoch = Instant::now();
    let started = Arc::new(Mutex::new(None));
    let observed = started.clone();
    let once = component("prepare", &[], ONCE, FATAL, 10, |mut context| async move {
        assert!(context.ready());
        assert!(!context.ready());
        sleep(Duration::from_secs(5)).await;
        Ok(())
    });
    let dependent = component(
        "consume",
        &["prepare"],
        ONCE,
        FATAL,
        1,
        move |_| async move {
            *observed.lock().unwrap() = Some(epoch.elapsed());
            Ok(())
        },
    );
    let report = Supervisor::new(vec![once, dependent])
        .unwrap()
        .run(receiver)
        .await;
    assert_eq!(*started.lock().unwrap(), Some(Duration::from_secs(5)));
    assert_eq!(report.cause, StopCause::Finished);
    assert!(
        report
            .outcomes
            .iter()
            .all(|outcome| outcome.state == ComponentState::Completed)
    );
}
#[tokio::test(start_paused = true)]
async fn ready_then_immediate_exit_never_starts_dependent() {
    for fail in [false, true] {
        let (_stop, receiver) = stop_channel();
        let effects = Arc::new(Mutex::new(0));
        let changed = effects.clone();
        let provider = component(
            "provider",
            &[],
            LONG,
            FATAL,
            2,
            move |mut context| async move {
                context.ready();
                if fail {
                    Err(AdapterError {
                        code: "start-failed",
                    })
                } else {
                    Ok(())
                }
            },
        );
        let dependent = component(
            "dependent",
            &["provider"],
            ONCE,
            FATAL,
            2,
            move |_| async move {
                *changed.lock().unwrap() += 1;
                Ok(())
            },
        );
        let report = Supervisor::new(vec![provider, dependent])
            .unwrap()
            .run(receiver)
            .await;
        assert_eq!(*effects.lock().unwrap(), 0);
        assert_eq!(report.failures[0].component, "provider");
        assert_eq!(
            report.failures[0].kind,
            if fail {
                FailureKind::Adapter("start-failed")
            } else {
                FailureKind::UnexpectedExit
            }
        );
    }
}
#[tokio::test(start_paused = true)]
async fn readiness_at_deadline_and_late_one_shot_completion_time_out() {
    for kind in [LONG, ONCE] {
        let (_stop, receiver) = stop_channel();
        let late = component("late", &[], kind, FATAL, 3, move |mut context| async move {
            sleep(Duration::from_secs(3)).await;
            context.ready();
            if kind == ONCE {
                return Ok(());
            }
            cooperative(context).await
        });
        let report = Supervisor::new(vec![late]).unwrap().run(receiver).await;
        assert_eq!(report.failures[0].kind, FailureKind::StartupTimeout);
        assert!(
            !report
                .transitions
                .iter()
                .any(|event| event.state == ComponentState::Ready)
        );
    }
}
#[tokio::test(start_paused = true)]
async fn readiness_just_before_deadline_succeeds() {
    let (stop, receiver) = stop_channel();
    let adapter = component("slow", &[], LONG, FATAL, 3, move |mut context| async move {
        sleep(Duration::from_millis(2999)).await;
        context.ready();
        sleep(Duration::from_millis(2)).await;
        stop.stop();
        cooperative(context).await
    });
    let report = Supervisor::new(vec![adapter]).unwrap().run(receiver).await;
    assert!(report.failures.is_empty());
}
#[tokio::test(start_paused = true)]
async fn worker_failure_has_no_self_wait_and_preserves_primary_over_cleanup_error() {
    let (_stop, receiver) = stop_channel();
    let provider = component("provider", &[], LONG, FATAL, 2, |mut context| async move {
        context.ready();
        context.changed().await;
        Err(AdapterError {
            code: "cleanup-failed",
        })
    });
    let failing = component("worker", &["provider"], LONG, FATAL, 2, |_| async {
        Err(AdapterError {
            code: "original-failure",
        })
    });
    let report = Supervisor::new(vec![provider, failing])
        .unwrap()
        .run(receiver)
        .await;
    assert_eq!(
        report.cause,
        StopCause::Fatal(ComponentFailure {
            component: "worker".into(),
            kind: FailureKind::Adapter("original-failure")
        })
    );
    assert_eq!(
        report.cleanup_failures,
        [CleanupFailure {
            component: "provider".into(),
            kind: CleanupKind::Adapter("cleanup-failed")
        }]
    );
}
#[tokio::test(start_paused = true)]
async fn optional_failure_leaves_unrelated_ready_component_running() {
    let (stop, receiver) = stop_channel();
    let epoch = Instant::now();
    let core = component("core", &[], LONG, FATAL, 3, move |mut context| async move {
        context.ready();
        context.changed().await;
        assert!(epoch.elapsed() >= Duration::from_secs(5));
        Ok(())
    });
    let optional = component("optional", &["core"], ONCE, OPTIONAL, 2, |_| async {
        Err(AdapterError {
            code: "deploy-failed",
        })
    });
    let observer = component(
        "observer",
        &["core"],
        ONCE,
        FATAL,
        10,
        move |_| async move {
            sleep(Duration::from_secs(5)).await;
            stop.stop();
            Ok(())
        },
    );
    let report = Supervisor::new(vec![core, optional, observer])
        .unwrap()
        .run(receiver)
        .await;
    assert_eq!(report.cause, StopCause::Requested);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].component, "optional");
    assert!(report.cleanup_failures.is_empty());
}
#[tokio::test(start_paused = true)]
async fn preexisting_and_repeated_stop_never_start_adapters() {
    let (stop, receiver) = stop_channel();
    assert!(stop.stop());
    assert!(!stop.stop());
    let effects = Arc::new(Mutex::new(0));
    let observed = effects.clone();
    let adapter = component("never", &[], LONG, FATAL, 1, move |_| async move {
        *observed.lock().unwrap() += 1;
        Ok(())
    });
    let report = Supervisor::new(vec![adapter]).unwrap().run(receiver).await;
    assert_eq!(*effects.lock().unwrap(), 0);
    assert_eq!(report.cause, StopCause::Requested);
}
#[tokio::test(start_paused = true)]
async fn partial_startup_stops_active_adapter_and_blocks_waiting_dependent() {
    let (stop, receiver) = stop_channel();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let events = observed.clone();
    let active = component(
        "starting",
        &[],
        LONG,
        FATAL,
        10,
        move |mut context| async move {
            events.lock().unwrap().push("started");
            context.changed().await;
            events.lock().unwrap().push("stopped");
            Ok(())
        },
    );
    let dependent = component("pending", &["starting"], ONCE, FATAL, 1, |_| async {
        panic!("dependent started without readiness")
    });
    let request = tokio::spawn(async move {
        sleep(Duration::from_secs(2)).await;
        assert!(stop.stop());
        assert!(!stop.stop());
    });
    let report = Supervisor::new(vec![active, dependent])
        .unwrap()
        .run(receiver)
        .await;
    request.await.unwrap();
    assert_eq!(*observed.lock().unwrap(), ["started", "stopped"]);
    assert!(report.failures.is_empty());
}
#[tokio::test(start_paused = true)]
async fn shutdown_waits_for_transitive_dependents_before_provider() {
    let (stop, receiver) = stop_channel();
    let log = Arc::new(Mutex::new(Vec::new()));
    let provider_log = log.clone();
    let consumer_log = log.clone();
    let provider = component(
        "provider",
        &[],
        LONG,
        FATAL,
        2,
        move |mut context| async move {
            context.ready();
            context.changed().await;
            provider_log.lock().unwrap().push("provider");
            Ok(())
        },
    );
    let prepared = component("prepared", &["provider"], ONCE, FATAL, 2, |_| async {
        Ok(())
    });
    let consumer = component(
        "consumer",
        &["prepared"],
        LONG,
        FATAL,
        2,
        move |mut context| async move {
            context.ready();
            stop.stop();
            context.changed().await;
            sleep(Duration::from_secs(2)).await;
            consumer_log.lock().unwrap().push("consumer");
            Ok(())
        },
    );
    let report = Supervisor::new(vec![provider, prepared, consumer])
        .unwrap()
        .run(receiver)
        .await;
    assert_eq!(*log.lock().unwrap(), ["consumer", "provider"]);
    assert!(report.cleanup_failures.is_empty());
}
#[tokio::test(start_paused = true)]
async fn stalled_shutdown_uses_one_global_budget_and_joins_aborted_futures() {
    struct Alive(Arc<Mutex<usize>>);
    impl Drop for Alive {
        fn drop(&mut self) {
            *self.0.lock().unwrap() -= 1;
        }
    }
    let (stop, receiver) = stop_channel();
    let alive = Arc::new(Mutex::new(0));
    let epoch = Instant::now();
    let mut registrations = Vec::new();
    for (name, deps) in [("a", vec![]), ("b", vec!["a"]), ("c", vec!["b"])] {
        let active = alive.clone();
        let request = stop.clone();
        registrations.push(component(
            name,
            &deps,
            LONG,
            FATAL,
            5,
            move |mut context| async move {
                *active.lock().unwrap() += 1;
                let _guard = Alive(active);
                context.ready();
                if name == "c" {
                    request.stop();
                }
                pending::<()>().await;
                Ok(())
            },
        ));
    }
    let report = Supervisor::new(registrations).unwrap().run(receiver).await;
    assert_eq!(epoch.elapsed(), SHUTDOWN_LIMIT);
    assert_eq!(*alive.lock().unwrap(), 0);
    assert_eq!(
        report
            .cleanup_failures
            .iter()
            .filter(|failure| failure.kind == CleanupKind::Forced)
            .count(),
        3
    );
    assert_eq!(
        report
            .cleanup_failures
            .iter()
            .filter(|failure| failure.kind == CleanupKind::AbortedAtDeadline)
            .count(),
        3
    );
}
#[tokio::test(start_paused = true)]
async fn force_phase_can_finish_before_final_abort_deadline() {
    let (stop, receiver) = stop_channel();
    let epoch = Instant::now();
    let adapter = component(
        "force-aware",
        &[],
        LONG,
        FATAL,
        2,
        move |mut context| async move {
            context.ready();
            stop.stop();
            while context.stop_phase() != StopPhase::Force {
                context.changed().await;
            }
            Ok(())
        },
    );
    let report = Supervisor::new(vec![adapter]).unwrap().run(receiver).await;
    assert_eq!(epoch.elapsed(), GRACE_PERIOD);
    assert_eq!(report.cleanup_failures.len(), 1);
    assert_eq!(report.cleanup_failures[0].kind, CleanupKind::Forced);
}
#[tokio::test(start_paused = true)]
async fn optional_dependency_failure_blocks_only_affected_subgraph() {
    let (_stop, receiver) = stop_channel();
    let bad = component("bad", &[], ONCE, OPTIONAL, 1, |_| async {
        Err(AdapterError { code: "optional" })
    });
    let blocked = component("blocked", &["bad"], ONCE, OPTIONAL, 1, |_| async {
        panic!("blocked dependency executed")
    });
    let good = component("good", &[], ONCE, FATAL, 1, |_| async { Ok(()) });
    let report = Supervisor::new(vec![bad, blocked, good])
        .unwrap()
        .run(receiver)
        .await;
    assert_eq!(report.cause, StopCause::Finished);
    assert_eq!(report.outcomes[1].state, ComponentState::Blocked);
    assert_eq!(report.outcomes[2].state, ComponentState::Completed);
    assert_eq!(report.failures.len(), 2);
}
#[tokio::test(start_paused = true)]
async fn losing_control_handles_requests_shutdown() {
    let (stop, receiver) = stop_channel();
    drop(stop);
    let adapter = component("never", &[], LONG, FATAL, 1, |_| async {
        panic!("closed control started adapter")
    });
    let report = Supervisor::new(vec![adapter]).unwrap().run(receiver).await;
    assert_eq!(report.cause, StopCause::ControlClosed);
}

#[test]
fn unrepresentable_startup_deadline_is_rejected_without_running_adapter() {
    let mut registration = component("overflow", &[], LONG, FATAL, 1, |_| async {
        panic!("must not execute")
    });
    registration.spec.startup_timeout = Duration::MAX;
    assert!(matches!(
        Supervisor::new(vec![registration]),
        Err(GraphError::TimeoutOverflow(_))
    ));
}
#[tokio::test(start_paused = true)]
async fn post_readiness_failure_is_fatal_and_preserves_worker_identity() {
    let (_stop, receiver) = stop_channel();
    let adapter = component("health", &[], LONG, FATAL, 1, |mut context| async move {
        context.ready();
        sleep(Duration::from_secs(2)).await;
        Err(AdapterError {
            code: "health-failed",
        })
    });
    let report = Supervisor::new(vec![adapter]).unwrap().run(receiver).await;
    assert!(
        report
            .transitions
            .iter()
            .any(|event| event.state == ComponentState::Ready)
    );
    assert_eq!(
        report.cause,
        StopCause::Fatal(ComponentFailure {
            component: "health".into(),
            kind: FailureKind::Adapter("health-failed")
        })
    );
}
#[tokio::test(start_paused = true)]
async fn optional_timeout_cleanup_has_its_own_bound_without_stopping_core() {
    let (stop, receiver) = stop_channel();
    let epoch = Instant::now();
    let core = component("core", &[], LONG, FATAL, 1, move |mut context| async move {
        context.ready();
        context.changed().await;
        assert_eq!(epoch.elapsed(), Duration::from_secs(40));
        Ok(())
    });
    let optional = component("optional", &["core"], LONG, OPTIONAL, 2, |_| async {
        pending::<()>().await;
        Ok(())
    });
    let observer = component(
        "observer",
        &["core"],
        ONCE,
        FATAL,
        50,
        move |_| async move {
            sleep(Duration::from_secs(40)).await;
            stop.stop();
            Ok(())
        },
    );
    let report = Supervisor::new(vec![core, optional, observer])
        .unwrap()
        .run(receiver)
        .await;
    assert_eq!(report.cause, StopCause::Requested);
    assert_eq!(
        report.failures,
        [ComponentFailure {
            component: "optional".into(),
            kind: FailureKind::StartupTimeout
        }]
    );
    assert!(
        report
            .cleanup_failures
            .iter()
            .any(|error| error.component == "optional"
                && error.kind == CleanupKind::AbortedAtDeadline)
    );
}

#[tokio::test(start_paused = true)]
async fn timeout_preserves_adapter_error_as_secondary_evidence() {
    let (_stop, receiver) = stop_channel();
    let adapter = component("late-error", &[], LONG, FATAL, 2, |_| async {
        sleep(Duration::from_secs(2)).await;
        Err(AdapterError {
            code: "late-original",
        })
    });
    let report = Supervisor::new(vec![adapter]).unwrap().run(receiver).await;
    assert_eq!(
        report.cause,
        StopCause::Fatal(ComponentFailure {
            component: "late-error".into(),
            kind: FailureKind::StartupTimeout
        })
    );
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.kind == FailureKind::Adapter("late-original"))
            || report
                .cleanup_failures
                .iter()
                .any(|failure| failure.kind == CleanupKind::Adapter("late-original"))
    );
}
