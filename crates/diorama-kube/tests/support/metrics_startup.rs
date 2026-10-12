use std::time::Duration;

use diorama_supervisor::{
    CleanupKind, ComponentState, FailureKind, LifecycleObserver, StopCause, SupervisorReport,
};

pub(crate) async fn metrics_bound(observer: &mut LifecycleObserver) -> bool {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = observer.snapshot();
            if let Some(failure) = snapshot
                .failures
                .iter()
                .find(|failure| failure.component == "metrics")
            {
                assert_eq!(failure.kind, FailureKind::Adapter("metrics_bind_failed"));
                return false;
            }
            assert!(
                snapshot.cause.is_none(),
                "runtime stopped before metrics startup: {:?}",
                snapshot.cause
            );
            if snapshot.components.iter().any(|component| {
                component.component == "metrics" && component.state == ComponentState::Ready
            }) {
                return true;
            }
            observer
                .changed()
                .await
                .expect("runtime observer stays open during startup");
        }
    })
    .await
    .expect("metrics reports readiness or its actual bind failure")
}

pub(crate) fn assert_retryable_bind_failure(report: &SupervisorReport) {
    assert_eq!(report.cause, StopCause::Requested);
    assert_eq!(
        report.failures.len(),
        1,
        "retry must not hide other component failures"
    );
    assert_eq!(report.failures[0].component, "metrics");
    assert_eq!(
        report.failures[0].kind,
        FailureKind::Adapter("metrics_bind_failed")
    );
    // Existing in-process normal and collision fixtures already report these
    // core deadlines. Retain them; these tests do not qualify cluster cleanup.
    for cleanup in &report.cleanup_failures {
        assert!(
            matches!(
                (cleanup.component.as_str(), &cleanup.kind),
                (
                    "local-path-provisioner" | "coredns" | "apiserver" | "datastore",
                    CleanupKind::Forced
                ) | (
                    "local-path-provisioner" | "coredns",
                    CleanupKind::AbortedAtDeadline
                )
            ),
            "unexpected cleanup failure in retry: {cleanup:?}"
        );
    }
    if !report.cleanup_failures.is_empty() {
        eprintln!(
            "characterized in-process core cleanup diagnostics: {:?}",
            report.cleanup_failures
        );
    }
}
