use diorama_supervisor::*;
use std::future::{Future, pending};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, advance};

struct Worker<F>(F);
impl<F, Fut> Adapter for Worker<F>
where
    F: FnOnce(AdapterContext) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), AdapterError>> + Send + 'static,
{
    fn run(self: Box<Self>, context: AdapterContext) -> AdapterFuture {
        Box::pin((self.0)(context))
    }
}
fn registration<F, Fut>(id: &str, policy: FailurePolicy, worker: F) -> Registration
where
    F: FnOnce(AdapterContext) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), AdapterError>> + Send + 'static,
{
    Registration::new(
        ComponentSpec {
            id: id.into(),
            prerequisites: vec![],
            kind: ComponentKind::LongRunning,
            failure_policy: policy,
            startup_timeout: Duration::from_mins(1),
        },
        Worker(worker),
    )
}
async fn until(
    observer: &mut LifecycleObserver,
    predicate: impl Fn(&LifecycleSnapshot) -> bool,
) -> Arc<LifecycleSnapshot> {
    loop {
        let snapshot = observer.snapshot();
        if predicate(&snapshot) {
            return snapshot;
        }
        observer.changed().await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn optional_failure_is_visible_while_healthy_worker_remains_responsive() {
    let (ping, mut requests) = mpsc::channel::<oneshot::Sender<()>>(1);
    let (fail, failed) = oneshot::channel();
    let secret = String::from("synthetic-secret-never-diagnostic");
    let registrations = vec![
        registration(
            "core",
            FailurePolicy::Fatal,
            move |mut context| async move {
                context.ready();
                loop {
                    tokio::select! {
                        request = requests.recv() => { request.unwrap().send(()).unwrap(); },
                        _ = context.changed() => return Ok(()),
                    }
                }
            },
        ),
        registration(
            "optional",
            FailurePolicy::Degrade,
            move |mut context| async move {
                context.ready();
                failed.await.unwrap();
                assert!(!secret.is_empty());
                Err(AdapterError {
                    code: "optional_failed",
                })
            },
        ),
    ];
    let (supervisor, mut observer) = Supervisor::new(registrations).unwrap().with_observer();
    assert!(
        observer
            .snapshot()
            .components
            .iter()
            .all(|c| c.state == ComponentState::Pending)
    );
    let (stop, receiver) = stop_channel();
    let running = tokio::spawn(supervisor.run(receiver));
    until(&mut observer, |s| {
        s.components
            .iter()
            .all(|c| c.state == ComponentState::Ready)
    })
    .await;
    fail.send(()).unwrap();
    let snapshot = until(&mut observer, |s| s.degraded).await;
    assert_eq!(snapshot.cause, None);
    assert!(!snapshot.finished);
    assert_eq!(
        snapshot.failures[0].kind,
        FailureKind::Adapter("optional_failed")
    );
    assert!(!format!("{snapshot:?}").contains("synthetic-secret-never-diagnostic"));
    let (answer, reply) = oneshot::channel();
    ping.send(answer).await.unwrap();
    reply.await.unwrap();
    stop.stop();
    running.await.unwrap();
    let final_snapshot = until(&mut observer, |s| s.finished).await;
    assert!(final_snapshot.degraded);
    assert_eq!(final_snapshot.cause, Some(StopCause::Requested));
    // Consume the final unseen value before testing publisher closure.
    while observer.changed().await.is_ok() {}
    assert!(observer.snapshot().finished);
}

#[tokio::test(start_paused = true)]
async fn fatal_cause_and_cleanup_error_survive_coalescing_and_final_close() {
    let (fail, failed) = oneshot::channel();
    let registrations = vec![
        registration("fatal", FailurePolicy::Fatal, move |_| async move {
            failed.await.unwrap();
            Err(AdapterError { code: "original" })
        }),
        registration("cleanup", FailurePolicy::Fatal, |mut context| async move {
            context.ready();
            context.changed().await;
            Err(AdapterError {
                code: "cleanup_failed",
            })
        }),
    ];
    let (supervisor, mut observer) = Supervisor::new(registrations).unwrap().with_observer();
    let held = observer.snapshot();
    let (_stop, receiver) = stop_channel();
    let task = tokio::spawn(supervisor.run(receiver));
    until(&mut observer, |s| {
        s.components[1].state == ComponentState::Ready
    })
    .await;
    fail.send(()).unwrap();
    let report = task.await.unwrap();
    let latest = observer.changed().await.unwrap();
    assert!(latest.finished);
    assert_eq!(latest.cause, Some(report.cause));
    assert_eq!(latest.cleanup_failures, report.cleanup_failures);
    assert_eq!(latest.failures, report.failures);
    assert_eq!(
        latest.cleanup_failures[0].kind,
        CleanupKind::Adapter("cleanup_failed")
    );
    assert_eq!(held.components[0].state, ComponentState::Pending);
    assert_eq!(observer.changed().await, Err(ObserverClosed));
}

#[tokio::test(start_paused = true)]
async fn slow_start_has_monotonic_deadline_and_abort_never_claims_finished() {
    let (supervisor, mut observer) =
        Supervisor::new(vec![registration("slow", FailurePolicy::Fatal, |_| {
            pending()
        })])
        .unwrap()
        .with_observer();
    let (_stop, receiver) = stop_channel();
    let task = tokio::spawn(supervisor.run(receiver));
    let started = until(&mut observer, |s| {
        s.components[0].state == ComponentState::Starting
    })
    .await;
    let component = &started.components[0];
    assert_eq!(component.kind, ComponentKind::LongRunning);
    assert_eq!(component.failure_policy, FailurePolicy::Fatal);
    assert_eq!(
        component.startup_deadline.unwrap() - component.state_since,
        Duration::from_mins(1)
    );
    advance(Duration::from_secs(5)).await;
    assert_eq!(
        Instant::now() - component.state_since,
        Duration::from_secs(5)
    );
    assert!(!observer.snapshot().finished);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    while observer.changed().await.is_ok() {}
    assert!(!observer.snapshot().finished);
}

#[tokio::test(start_paused = true)]
async fn unpolled_and_dropped_observers_do_not_extend_shutdown_or_hold_borrow_locks() {
    for keep in [true, false] {
        let (supervisor, observer) =
            Supervisor::new(vec![registration("stalled", FailurePolicy::Fatal, |_| {
                pending()
            })])
            .unwrap()
            .with_observer();
        let (supervisor, second) = supervisor.with_observer();
        let held = observer.snapshot();
        let observer = keep.then_some(observer);
        drop(second);
        let (stop, receiver) = stop_channel();
        let task = tokio::spawn(supervisor.run(receiver));
        tokio::task::yield_now().await;
        let began = Instant::now();
        stop.stop();
        let report = task.await.unwrap();
        assert_eq!(began.elapsed(), SHUTDOWN_LIMIT);
        assert_eq!(report.cause, StopCause::Requested);
        assert!(
            report
                .cleanup_failures
                .iter()
                .any(|failure| failure.kind == CleanupKind::AbortedAtDeadline)
        );
        assert_eq!(held.components[0].state, ComponentState::Pending);
        if let Some(observer) = observer {
            assert!(observer.snapshot().finished);
        }
    }
}

#[tokio::test]
async fn dropping_unrun_publisher_is_distinct_from_completed_empty_graph() {
    let (supervisor, mut observer) = Supervisor::new(vec![]).unwrap().with_observer();
    drop(supervisor);
    assert_eq!(observer.changed().await, Err(ObserverClosed));
    assert!(!observer.snapshot().finished);
    let (supervisor, mut observer) = Supervisor::new(vec![]).unwrap().with_observer();
    let (_stop, receiver) = stop_channel();
    supervisor.run(receiver).await;
    let final_snapshot = observer.changed().await.unwrap();
    assert!(final_snapshot.finished);
    assert_eq!(final_snapshot.cause, Some(StopCause::Finished));
    assert_eq!(observer.changed().await, Err(ObserverClosed));
}
