//! Explicit process-lifetime Unix signal handling around one supervisor.
use crate::{Supervisor, SupervisorReport, stop_channel};
use std::fmt;
use std::future::Future;
use std::io;
use tokio::signal::unix::{Signal, SignalKind, signal};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownSignal {
    Interrupt,
    Terminate,
}

/// Installation failure before any adapter is polled. Raw OS text is not exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalInstallError {
    pub signal: ShutdownSignal,
    pub kind: io::ErrorKind,
}
impl fmt::Display for SignalInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot install {:?} listener: {:?}",
            self.signal, self.kind
        )
    }
}
impl std::error::Error for SignalInstallError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalRunReport {
    pub supervisor: SupervisorReport,
    /// First signal observed by this bridge; concurrent Unix deliveries may coalesce.
    pub first_signal: Option<ShutdownSignal>,
    /// Unexpected listener end requests cleanup without pretending a signal arrived.
    pub listener_closed: Option<ShutdownSignal>,
}

trait Notifications {
    fn next(&mut self) -> impl Future<Output = Option<()>> + Send;
}
impl Notifications for Signal {
    async fn next(&mut self) -> Option<()> {
        self.recv().await
    }
}

fn install() -> Result<(Signal, Signal), SignalInstallError> {
    let interrupt = signal(SignalKind::interrupt()).map_err(|error| SignalInstallError {
        signal: ShutdownSignal::Interrupt,
        kind: error.kind(),
    })?;
    let terminate = signal(SignalKind::terminate()).map_err(|error| SignalInstallError {
        signal: ShutdownSignal::Terminate,
        kind: error.kind(),
    })?;
    Ok((interrupt, terminate))
}

/// Install SIGINT/SIGTERM listeners before starting adapters and run through cleanup.
///
/// Must be polled inside a Tokio runtime with its I/O driver enabled. Listener
/// registration changes process-wide signal behavior permanently; dropping this
/// future does not restore the default handlers or await supervisor cleanup.
/// Intended for a dedicated executable lifetime, never implicit library startup.
/// Repeated signals request the same stop and never reset the supervisor budget.
pub async fn run_with_signals(
    supervisor: Supervisor,
) -> Result<SignalRunReport, SignalInstallError> {
    run_with_install(supervisor, install).await
}

async fn run_with_install<S: Notifications>(
    supervisor: Supervisor,
    installer: impl FnOnce() -> Result<(S, S), SignalInstallError>,
) -> Result<SignalRunReport, SignalInstallError> {
    let (interrupt, terminate) = installer()?;
    Ok(drive(supervisor, interrupt, terminate).await)
}

async fn drive<S: Notifications>(
    supervisor: Supervisor,
    mut interrupt: S,
    mut terminate: S,
) -> SignalRunReport {
    let (stop, receiver) = stop_channel();
    let running = supervisor.run(receiver);
    tokio::pin!(running);
    let mut first_signal = None;
    let mut listener_closed = None;
    let mut interrupt_open = true;
    let mut terminate_open = true;
    loop {
        // The supervisor always gets a poll, even during a stream of signals.
        // It retains authority over its first fatal cause and shutdown deadlines.
        let (which, notification) = tokio::select! {
            biased;
            report = &mut running => return SignalRunReport {
                supervisor: report, first_signal, listener_closed,
            },
            notification = interrupt.next(), if interrupt_open => (ShutdownSignal::Interrupt, notification),
            notification = terminate.next(), if terminate_open => (ShutdownSignal::Terminate, notification),
        };
        if notification.is_some() {
            first_signal.get_or_insert(which);
        } else {
            listener_closed.get_or_insert(which);
            match which {
                ShutdownSignal::Interrupt => interrupt_open = false,
                ShutdownSignal::Terminate => terminate_open = false,
            }
        }
        stop.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Adapter, AdapterContext, AdapterFuture, ComponentKind, ComponentSpec, FailurePolicy,
        Registration, StopCause, StopPhase,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::sync::mpsc;

    impl Notifications for mpsc::UnboundedReceiver<()> {
        async fn next(&mut self) -> Option<()> {
            self.recv().await
        }
    }
    struct Count(Arc<AtomicUsize>);
    impl Adapter for Count {
        fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                context.ready();
                while context.stop_phase() == StopPhase::Running {
                    context.changed().await;
                }
                Ok(())
            })
        }
    }
    fn supervisor(count: Arc<AtomicUsize>) -> Supervisor {
        Supervisor::new(vec![Registration::new(
            ComponentSpec {
                id: "fixture".into(),
                prerequisites: vec![],
                kind: ComponentKind::LongRunning,
                failure_policy: FailurePolicy::Fatal,
                startup_timeout: Duration::from_secs(1),
            },
            Count(count),
        )])
        .unwrap()
    }
    #[tokio::test]
    async fn installation_failure_has_no_adapter_effects_and_no_raw_message() {
        let count = Arc::new(AtomicUsize::new(0));
        let error =
            run_with_install::<mpsc::UnboundedReceiver<()>>(supervisor(count.clone()), || {
                Err(SignalInstallError {
                    signal: ShutdownSignal::Terminate,
                    kind: io::ErrorKind::PermissionDenied,
                })
            })
            .await
            .unwrap_err();
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_eq!(
            error.to_string(),
            "cannot install Terminate listener: PermissionDenied"
        );
    }
    #[tokio::test]
    async fn listener_end_requests_stop_without_a_fake_signal_or_busy_loop() {
        let (interrupt, int_rx) = mpsc::unbounded_channel();
        drop(interrupt);
        let (_terminate, term_rx) = mpsc::unbounded_channel();
        let report = drive(supervisor(Arc::new(AtomicUsize::new(0))), int_rx, term_rx).await;
        assert_eq!(report.first_signal, None);
        assert_eq!(report.listener_closed, Some(ShutdownSignal::Interrupt));
        assert_eq!(report.supervisor.cause, StopCause::Requested);
        assert!(report.supervisor.cleanup_failures.is_empty());
    }
    #[tokio::test(start_paused = true)]
    async fn repeated_notifications_do_not_extend_shutdown_budget() {
        struct Stalled;
        impl Adapter for Stalled {
            fn run(self: Box<Self>, _context: AdapterContext) -> AdapterFuture {
                Box::pin(std::future::pending())
            }
        }
        let supervisor = Supervisor::new(vec![Registration::new(
            ComponentSpec {
                id: "stalled".into(),
                prerequisites: vec![],
                kind: ComponentKind::LongRunning,
                failure_policy: FailurePolicy::Fatal,
                startup_timeout: Duration::from_mins(1),
            },
            Stalled,
        )])
        .unwrap();
        let (interrupt, int_rx) = mpsc::unbounded_channel();
        let (terminate, term_rx) = mpsc::unbounded_channel();
        interrupt.send(()).unwrap();
        let epoch = tokio::time::Instant::now();
        let repeated = tokio::spawn(async move {
            for seconds in [10, 20, 29, 34] {
                tokio::time::sleep_until(epoch + Duration::from_secs(seconds)).await;
                terminate.send(()).unwrap();
            }
            // Keep the notification sources alive until the supervisor deadline.
            tokio::time::sleep_until(epoch + crate::SHUTDOWN_LIMIT).await;
            drop((interrupt, terminate));
        });
        let report = drive(supervisor, int_rx, term_rx).await;
        repeated.await.unwrap();
        assert_eq!(epoch.elapsed(), crate::SHUTDOWN_LIMIT);
        assert_eq!(report.first_signal, Some(ShutdownSignal::Interrupt));
        assert_eq!(report.supervisor.cause, StopCause::Requested);
        assert!(
            report
                .supervisor
                .cleanup_failures
                .iter()
                .any(|failure| failure.kind == crate::CleanupKind::AbortedAtDeadline)
        );
    }
}
