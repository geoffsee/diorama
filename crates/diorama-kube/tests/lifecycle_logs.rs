use diorama::lifecycle_logs::*;
use diorama_supervisor::*;
use serde_json::Value;
use std::future::{Future, pending};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

fn snapshot() -> LifecycleSnapshot {
    let now = Instant::now();
    LifecycleSnapshot {
        published_at: now,
        components: vec![ComponentDiagnostic {
            component: "core".into(),
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Fatal,
            state: ComponentState::Starting,
            state_since: now,
            startup_deadline: Some(now + Duration::from_secs(10)),
        }],
        cause: None,
        failures: vec![],
        cleanup_failures: vec![],
        degraded: false,
        finished: false,
    }
}
fn values(batch: &RenderedBatch) -> Vec<Value> {
    batch
        .frames
        .iter()
        .map(|f| serde_json::from_str(f.as_str()).unwrap())
        .collect()
}
#[test]
fn deterministic_jsonl_escaping_debug_filter_and_monotonic_time() {
    let mut state = snapshot();
    state.components[0].component = "line\n\"quote\\雪".into();
    state.published_at += Duration::from_secs(3);
    let mut renderer = LifecycleRenderer::new(LogLevel::from_debug(true));
    let batch = renderer.render(&state).unwrap();
    assert_eq!(batch.frames.len(), 1);
    assert_eq!(
        batch.frames[0].as_str(),
        "{\"component\":\"line\\n\\\"quote\\\\雪\",\"event\":\"component_state\",\"kind\":\"long_running\",\"level\":\"debug\",\"policy\":\"fatal\",\"schema\":1,\"startup_remaining_ms\":7000,\"state\":\"starting\",\"state_age_ms\":3000}\n"
    );
    assert_eq!(batch.frames[0].as_str().lines().count(), 1);
    assert_eq!(
        renderer.render(&state).unwrap().frames,
        <[diorama::lifecycle_logs::LogFrame; 0]>::default()
    );
    let quiet = LifecycleRenderer::new(LogLevel::from_debug(false))
        .render(&state)
        .unwrap();
    assert_eq!(
        quiet.frames,
        <[diorama::lifecycle_logs::LogFrame; 0]>::default()
    );
    assert_eq!(quiet.filtered, 1);
}
#[test]
fn all_thresholds_preserve_severe_records_and_deduplicate_retained_causes() {
    let mut state = snapshot();
    state.components[0].failure_policy = FailurePolicy::Degrade;
    state.failures.push(ComponentFailure {
        component: "core".into(),
        kind: FailureKind::Adapter("unavailable"),
    });
    state.cleanup_failures.push(CleanupFailure {
        component: "core".into(),
        kind: CleanupKind::Forced,
    });
    state.degraded = true;
    state.finished = true;
    state.cause = Some(StopCause::Requested);
    for (level, count, filtered) in [
        (LogLevel::Error, 1, 5),
        (LogLevel::Warn, 2, 4),
        (LogLevel::Info, 5, 1),
        (LogLevel::Debug, 6, 0),
    ] {
        let mut renderer = LifecycleRenderer::new(level);
        let batch = renderer.render(&state).unwrap();
        assert_eq!(batch.frames.len(), count);
        assert_eq!(batch.filtered, filtered);
        assert_eq!(values(&batch)[0]["detail_code"], "unavailable");
        assert_eq!(
            renderer.render(&state).unwrap().frames,
            <[diorama::lifecycle_logs::LogFrame; 0]>::default()
        );
    }
}
#[test]
fn changed_graph_rewritten_history_and_oversized_inputs_fail_without_echo() {
    let state = snapshot();
    let mut renderer = LifecycleRenderer::new(LogLevel::Info);
    renderer.render(&state).unwrap();
    let mut changed = state.clone();
    changed.components[0].component = "different".into();
    assert_eq!(
        renderer.render(&changed).unwrap_err(),
        RenderError::GraphChanged
    );
    let mut invalid = state.clone();
    invalid.components[0].component = "secret".repeat(100);
    let error = renderer.render(&invalid).unwrap_err();
    assert_eq!(error, RenderError::InputLimit);
    assert!(!format!("{error:?}").contains("secret"));
    let mut failed = state;
    failed.failures.push(ComponentFailure {
        component: "core".into(),
        kind: FailureKind::Adapter("first"),
    });
    renderer.render(&failed).unwrap();
    failed.failures.clear();
    assert_eq!(
        renderer.render(&failed).unwrap_err(),
        RenderError::HistoryChanged
    );
    let mut too_many = snapshot();
    too_many.components = vec![too_many.components[0].clone(); MAX_COMPONENTS + 1];
    assert_eq!(
        LifecycleRenderer::new(LogLevel::Debug)
            .render(&too_many)
            .unwrap_err(),
        RenderError::InputLimit
    );
}
#[test]
fn batch_memory_is_capped_and_oversize_records_are_counted() {
    let mut state = snapshot();
    state.components = (0..MAX_COMPONENTS)
        .map(|i| {
            let mut component = state.components[0].clone();
            component.component = format!("{i}{}", "\u{1}".repeat(240));
            component
        })
        .collect();
    let batch = LifecycleRenderer::new(LogLevel::Debug)
        .render(&state)
        .unwrap();
    assert_eq!(
        batch.frames.len() as u64 + batch.oversize,
        MAX_COMPONENTS as u64
    );
    assert!(batch.oversize > 0);
    assert!(
        batch
            .frames
            .iter()
            .all(|f| f.as_str().len() <= MAX_FRAME_BYTES)
    );
    assert!(batch.frames.iter().map(|f| f.as_str().len()).sum::<usize>() <= MAX_BATCH_BYTES);
    assert!(log_channel(0).is_err());
    assert!(log_channel(MAX_QUEUE_CAPACITY + 1).is_err());
}

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
fn registration<F, Fut>(id: &str, policy: FailurePolicy, run: F) -> Registration
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
        Worker(run),
    )
}
#[tokio::test(start_paused = true)]
async fn optional_failure_is_logged_while_healthy_worker_answers_without_secret() {
    let (fail, failed) = oneshot::channel();
    let (ping, mut requests) = mpsc::channel::<oneshot::Sender<()>>(1);
    let secret = "private-adapter-token".to_string();
    let (supervisor,observer)=Supervisor::new(vec![
        registration("optional",FailurePolicy::Degrade,move |_|async move {failed.await.unwrap();assert_ne!(secret, "");Err(AdapterError{code:"optional_failed"})}),
        registration("core",FailurePolicy::Fatal,move |mut context|async move {context.ready();loop{tokio::select!{request=requests.recv()=>{request.unwrap().send(()).unwrap();},_=context.changed()=>return Ok(())}}}),
    ]).unwrap().with_observer();
    let (sender, mut receiver) = log_channel(64).unwrap();
    let logging = tokio::spawn(consume_lifecycle(
        observer,
        LifecycleRenderer::new(LogLevel::Info),
        sender,
    ));
    let (stop, control) = stop_channel();
    let running = tokio::spawn(supervisor.run(control));
    fail.send(()).unwrap();
    loop {
        let frame = receiver.recv().await.unwrap();
        assert!(!frame.as_str().contains("private-adapter-token"));
        let value: Value = serde_json::from_str(frame.as_str()).unwrap();
        if value["event"] == "component_failure" {
            assert_eq!(value["detail_code"], "optional_failed");
            break;
        }
    }
    let (answer, reply) = oneshot::channel();
    ping.send(answer).await.unwrap();
    reply.await.unwrap();
    stop.stop();
    let report = running.await.unwrap();
    assert_eq!(report.cause, StopCause::Requested);
    let delivered = logging.await.unwrap();
    assert_eq!(delivered.publisher, PublisherStatus::Finished);
    assert_eq!(delivered.dropped_full, 0);
    assert_eq!(delivered.render_error, None);
}
#[tokio::test(start_paused = true)]
async fn unpolled_full_queue_never_extends_global_cleanup_budget() {
    let (supervisor, observer) =
        Supervisor::new(vec![registration("stalled", FailurePolicy::Fatal, |_| {
            pending()
        })])
        .unwrap()
        .with_observer();
    let (sender, mut receiver) = log_channel(1).unwrap();
    let logging = tokio::spawn(consume_lifecycle(
        observer,
        LifecycleRenderer::new(LogLevel::Debug),
        sender,
    ));
    tokio::task::yield_now().await; // Enqueue the initial Pending frame and leave it unread.
    let (stop, control) = stop_channel();
    let running = tokio::spawn(supervisor.run(control));
    tokio::task::yield_now().await;
    let began = Instant::now();
    stop.stop();
    let report = running.await.unwrap();
    assert_eq!(began.elapsed(), SHUTDOWN_LIMIT);
    assert_eq!(report.cause, StopCause::Requested);
    let delivered = logging.await.unwrap();
    assert_eq!(delivered.enqueued, 1);
    assert!(delivered.dropped_full > 0);
    assert_eq!(delivered.closed, 0);
    assert_eq!(delivered.publisher, PublisherStatus::Finished);
    assert!(receiver.recv().await.is_some());
    assert!(receiver.recv().await.is_none());
}
#[tokio::test(start_paused = true)]
async fn sink_close_and_publisher_cancel_have_distinct_bounded_outcomes() {
    let (supervisor, observer) = Supervisor::new(vec![]).unwrap().with_observer();
    let (sender, receiver) = log_channel(1).unwrap();
    drop(receiver);
    let report = consume_lifecycle(observer, LifecycleRenderer::new(LogLevel::Info), sender).await;
    assert_eq!(report.closed, 1);
    assert_eq!(report.publisher, PublisherStatus::Open);
    drop(supervisor);
    let (supervisor, observer) = Supervisor::new(vec![]).unwrap().with_observer();
    let (sender, _receiver) = log_channel(1).unwrap();
    drop(supervisor);
    let report = consume_lifecycle(observer, LifecycleRenderer::new(LogLevel::Info), sender).await;
    assert_eq!(report.publisher, PublisherStatus::Cancelled);
    assert_eq!(report.closed, 0);
}

#[tokio::test]
async fn completed_snapshot_has_exact_enqueue_full_closed_and_filter_counts() {
    for (level, close, enqueued, full, closed, filtered) in [
        (LogLevel::Info, false, 1, 1, 0, 0),
        (LogLevel::Info, true, 0, 0, 2, 0),
        (LogLevel::Error, false, 0, 0, 0, 2),
    ] {
        let (supervisor, observer) = Supervisor::new(vec![]).unwrap().with_observer();
        let (_stop, control) = stop_channel();
        supervisor.run(control).await;
        let (sender, receiver) = log_channel(1).unwrap();
        let _receiver = if close {
            drop(receiver);
            None
        } else {
            Some(receiver)
        };
        let result = consume_lifecycle(observer, LifecycleRenderer::new(level), sender).await;
        assert_eq!(result.publisher, PublisherStatus::Finished);
        assert_eq!(
            (
                result.enqueued,
                result.dropped_full,
                result.closed,
                result.filtered
            ),
            (enqueued, full, closed, filtered)
        );
        assert_eq!(result.oversize, 0);
        assert_eq!(result.render_error, None);
    }
}

#[test]
fn invalid_dependency_identity_and_cause_replacement_are_rejected() {
    let mut state = snapshot();
    state.failures.push(ComponentFailure {
        component: "core".into(),
        kind: FailureKind::DependencyFailed("unknown".into()),
    });
    assert_eq!(
        LifecycleRenderer::new(LogLevel::Info)
            .render(&state)
            .unwrap_err(),
        RenderError::InvalidSnapshot
    );
    state.failures.clear();
    state.cause = Some(StopCause::Requested);
    let mut renderer = LifecycleRenderer::new(LogLevel::Info);
    renderer.render(&state).unwrap();
    state.cause = Some(StopCause::ControlClosed);
    assert_eq!(
        renderer.render(&state).unwrap_err(),
        RenderError::HistoryChanged
    );
}
