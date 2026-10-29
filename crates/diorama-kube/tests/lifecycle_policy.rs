use std::collections::BTreeMap;
use std::future::{Future, pending};
use std::time::Duration;

use diorama::lifecycle_policy::LifecyclePolicy;
use diorama_config::{
    EnvironmentMode, ExplicitFlags, HostContext, ValidatedConfig, decode, resolve_layers,
};
use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    ComponentState, FailureKind, FailurePolicy, Registration, StopCause, StopPhase, Supervisor,
    stop_channel,
};
use tokio::sync::oneshot;
use tokio::time::Instant;

fn resolve(
    file: &str,
    environment: &BTreeMap<String, String>,
    flags: &ExplicitFlags,
) -> ValidatedConfig {
    resolve_layers(
        Some(decode(file).unwrap()),
        environment,
        flags,
        EnvironmentMode::Include,
        &HostContext {
            cpu_count: 8,
            architecture: "arm64".into(),
            detected_container_mode: false,
        },
    )
    .unwrap()
    .validated
}
fn configured(value: &str) -> ValidatedConfig {
    resolve(
        &format!("kubernetes:\n  apiServer:\n    startupTimeoutSeconds: {value}\n"),
        &BTreeMap::new(),
        &ExplicitFlags::default(),
    )
}
fn component(id: &str) -> ComponentSpec {
    ComponentSpec {
        id: id.into(),
        prerequisites: vec![],
        kind: ComponentKind::LongRunning,
        failure_policy: FailurePolicy::Fatal,
        startup_timeout: Duration::from_secs(99),
    }
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
#[test]
fn default_nonpositive_and_positive_values_preserve_baseline_policy_without_changing_document() {
    let default = resolve("{}", &BTreeMap::new(), &ExplicitFlags::default());
    assert_eq!(
        LifecyclePolicy::from_config(&default).startup_timeout(),
        Duration::from_mins(10)
    );
    for (value, expected) in [
        ("0", 600),
        ("-9", 600),
        ("1", 1),
        ("17", 17),
        ("9223372036854775807", 9_223_372_036_854_775_807),
    ] {
        let config = configured(value);
        let policy = LifecyclePolicy::from_config(&config);
        assert_eq!(policy.startup_timeout(), Duration::from_secs(expected));
        assert_eq!(
            config
                .config()
                .kubernetes
                .api_server
                .startup_timeout_seconds
                .to_string(),
            value
        );
    }
}
#[test]
fn apply_changes_only_timeout_and_leaves_graph_validation_to_supervisor() {
    let policy = LifecyclePolicy::from_config(&configured("7"));
    let original = ComponentSpec {
        id: "optional".into(),
        prerequisites: vec!["provider".into()],
        kind: ComponentKind::OneShot,
        failure_policy: FailurePolicy::Degrade,
        startup_timeout: Duration::from_secs(99),
    };
    let mut expected = original.clone();
    expected.startup_timeout = Duration::from_secs(7);
    assert_eq!(policy.apply(original), expected);
}
#[tokio::test(start_paused = true)]
async fn real_layer_override_reaches_exact_component_deadline_and_cleans_partial_startup() {
    let config = resolve(
        "kubernetes:\n  apiServer:\n    startupTimeoutSeconds: 90\n",
        &BTreeMap::from([("DIORAMA_STARTUP_TIMEOUT".into(), "11".into())]),
        &ExplicitFlags(BTreeMap::from([("startup-timeout".into(), "2".into())])),
    );
    let policy = LifecyclePolicy::from_config(&config);
    assert_eq!(policy.startup_timeout(), Duration::from_secs(2));
    let (finished, cleanup) = oneshot::channel();
    let adapter = Worker(move |mut context: AdapterContext| async move {
        while context.stop_phase() == StopPhase::Running {
            context.changed().await;
        }
        finished.send(()).unwrap();
        Ok(())
    });
    let mut dependent = component("dependent");
    dependent.prerequisites.push("slow".into());
    let supervisor = Supervisor::new(vec![
        Registration::new(policy.apply(component("slow")), adapter),
        Registration::new(
            policy.apply(dependent),
            Worker(|_| async {
                Err(AdapterError {
                    code: "dependent_must_not_launch",
                })
            }),
        ),
    ])
    .unwrap();
    let (_stop, receiver) = stop_channel();
    let started = Instant::now();
    let report = supervisor.run(receiver).await;
    assert_eq!(started.elapsed(), Duration::from_secs(2));
    assert_eq!(report.failures[0].component, "slow");
    assert_eq!(report.failures[0].kind, FailureKind::StartupTimeout);
    assert_eq!(report.cause, StopCause::Fatal(report.failures[0].clone()));
    assert!(cleanup.await.is_ok());
    assert_eq!(
        report.cleanup_failures,
        <[diorama_supervisor::CleanupFailure; 0]>::default()
    );
    assert!(
        !report
            .transitions
            .iter()
            .any(|event| event.component == "dependent" && event.state == ComponentState::Starting)
    );
}
#[tokio::test(start_paused = true)]
async fn dependency_wait_does_not_spend_configured_child_budget() {
    let policy = LifecyclePolicy::from_config(&configured("2"));
    let mut provider = component("provider");
    provider.kind = ComponentKind::OneShot;
    let mut child = component("child");
    child.prerequisites.push("provider".into());
    let (ready, observed) = oneshot::channel();
    let supervisor = Supervisor::new(vec![
        Registration::new(
            policy.apply(provider),
            Worker(|_| async {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                Ok(())
            }),
        ),
        Registration::new(
            policy.apply(child),
            Worker(move |mut context: AdapterContext| async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                context.ready();
                ready.send(()).unwrap();
                while context.stop_phase() == StopPhase::Running {
                    context.changed().await;
                }
                Ok(())
            }),
        ),
    ])
    .unwrap();
    let (stop, receiver) = stop_channel();
    let started = Instant::now();
    let task = tokio::spawn(supervisor.run(receiver));
    observed.await.unwrap();
    assert_eq!(started.elapsed(), Duration::from_secs(3));
    stop.stop();
    let report = task.await.unwrap();
    assert_eq!(
        report.failures,
        <[diorama_supervisor::ComponentFailure; 0]>::default()
    );
    assert_eq!(
        report.cleanup_failures,
        <[diorama_supervisor::CleanupFailure; 0]>::default()
    );
}
#[test]
fn unrepresentable_effective_deadline_is_not_silently_clamped() {
    let policy = LifecyclePolicy::from_config(&configured("9223372036854775807"));
    let result = Supervisor::new(vec![Registration::new(
        policy.apply(component("huge")),
        Worker(|_| pending()),
    )]);
    assert!(result.is_err());
}
