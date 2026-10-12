//! Fixed Alpine prerequisite commands. No caller-provided executable or arguments.
use diorama_platform::preflight::PreparationAction;
use diorama_supervisor::process::{OwnedProcessAdapter, ProcessCleanupSnapshot, ProcessCommand};
use diorama_supervisor::{
    ComponentKind, ComponentSpec, FailurePolicy, Registration, StopCause, StopHandle, Supervisor,
    stop_channel,
};
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

/// Persistent invocation cancellation. It is deliberately local, like CLI output locks.
#[derive(Clone, Debug, Default)]
pub struct Cancellation(Rc<RefCell<CancelState>>);
#[derive(Debug, Default)]
struct CancelState {
    cancelled: bool,
    active: Option<StopHandle>,
}
impl Cancellation {
    pub fn cancel(&self) {
        let mut state = self.0.borrow_mut();
        state.cancelled = true;
        if let Some(active) = &state.active {
            active.stop();
        }
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.borrow().cancelled
    }
    fn register(&self, handle: StopHandle) -> bool {
        let mut state = self.0.borrow_mut();
        if state.cancelled {
            return false;
        }
        state.active = Some(handle);
        true
    }
    fn clear(&self) {
        self.0.borrow_mut().active = None;
    }
    /// Give the invocation bridge a chance to observe pending signals before effects.
    pub async fn checkpoint(&self) -> bool {
        tokio::task::yield_now().await;
        !self.is_cancelled()
    }
}
/// Only an explicitly parsed opt-in can construct this capability.
#[derive(Debug)]
pub struct PreparationPermit(());
impl PreparationPermit {
    pub fn from_options(options: crate::CheckOptions) -> Option<Self> {
        options.install_prerequisites.then_some(Self(()))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationStep {
    InstallPackages,
    RegisterCgroups,
    StartCgroups,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationFailure {
    InvalidAction,
    Cancelled,
    Graph,
    Command,
    Cleanup,
}
#[derive(Clone, Debug)]
pub struct CommandReceipt {
    pub step: PreparationStep,
    pub cause: StopCause,
    pub cleanup: ProcessCleanupSnapshot,
}
impl CommandReceipt {
    /// Distinguish an execution error from missing proof that the owned child was retired.
    pub fn cleanup_uncertain(&self) -> bool {
        let cleanup = &self.cleanup;
        if !cleanup.started
            || (!cleanup.spawned && cleanup.error == Some("process_owner_spawn_failed"))
        {
            return false;
        }
        !cleanup.thread_joined
            || cleanup.ownership_lost
            || (cleanup.spawned && !cleanup.leader_reaped)
    }
}
#[derive(Clone, Debug, Default)]
pub struct PreparationReceipt {
    pub commands: Vec<CommandReceipt>,
    pub failure: Option<PreparationFailure>,
}
impl PreparationReceipt {
    pub fn succeeded(&self) -> bool {
        self.failure.is_none()
    }
    /// Even a failed command can have changed packages or shared service state.
    pub fn shared_effects_possible(&self) -> bool {
        self.commands.iter().any(|command| command.cleanup.spawned)
    }
}
pub type PreparationFuture<'a> = Pin<Box<dyn Future<Output = PreparationReceipt> + 'a>>;
/// Injected typed action boundary. Return settled ownership or an explicit incomplete receipt;
/// callers must suppress further synchronous output/effects for the latter.
pub trait PreparationExecutor {
    fn execute<'a>(
        &'a mut self,
        action: PreparationAction,
        permit: &'a PreparationPermit,
        cancellation: &'a Cancellation,
    ) -> PreparationFuture<'a>;
}
#[derive(Debug, Default)]
pub struct AlpinePreparation;
impl PreparationExecutor for AlpinePreparation {
    fn execute<'a>(
        &'a mut self,
        action: PreparationAction,
        _permit: &'a PreparationPermit,
        cancellation: &'a Cancellation,
    ) -> PreparationFuture<'a> {
        Box::pin(async move {
            let mut receipt = PreparationReceipt::default();
            let steps: &[PreparationStep] = match action {
                PreparationAction::InstallAlpineNetworking {
                    nftables: false,
                    iptables: false,
                } => {
                    receipt.failure = Some(PreparationFailure::InvalidAction);
                    return receipt;
                },
                PreparationAction::InstallAlpineNetworking { .. } => {
                    &[PreparationStep::InstallPackages]
                },
                PreparationAction::EnableAlpineCgroups => &[
                    PreparationStep::RegisterCgroups,
                    PreparationStep::StartCgroups,
                ],
            };
            for &step in steps {
                if !cancellation.checkpoint().await {
                    receipt.failure = Some(PreparationFailure::Cancelled);
                    break;
                }
                let (command, timeout) = command(step, action);
                let result = run_command(step, command, timeout, cancellation).await;
                match result {
                    Ok(record) => {
                        let failed = command_failure(&record, cancellation);
                        receipt.commands.push(record);
                        receipt.failure = failed;
                    },
                    Err(error) => receipt.failure = Some(error),
                }
                if receipt.failure.is_some() {
                    break;
                }
            }
            receipt
        })
    }
}
fn command_failure(
    record: &CommandReceipt,
    cancellation: &Cancellation,
) -> Option<PreparationFailure> {
    if record.cleanup_uncertain() {
        return Some(PreparationFailure::Cleanup);
    }
    if cancellation.is_cancelled() {
        return Some(PreparationFailure::Cancelled);
    }
    if record.cause != StopCause::Finished
        || record.cleanup.exit.and_then(|exit| exit.code) != Some(0)
    {
        return Some(PreparationFailure::Command);
    }
    None
}
fn command(step: PreparationStep, action: PreparationAction) -> (ProcessCommand, Duration) {
    let (mut command, timeout) = match step {
        PreparationStep::InstallPackages => {
            let mut command = ProcessCommand::new("/sbin/apk")
                .arg("add")
                .arg("--no-cache");
            if let PreparationAction::InstallAlpineNetworking { nftables, iptables } = action {
                if nftables {
                    command = command.arg("nftables");
                }
                if iptables {
                    command = command.arg("iptables");
                }
            }
            (command, Duration::from_mins(5))
        },
        PreparationStep::RegisterCgroups => (
            ProcessCommand::new("/sbin/rc-update")
                .arg("add")
                .arg("cgroups")
                .arg("boot"),
            Duration::from_mins(1),
        ),
        PreparationStep::StartCgroups => (
            ProcessCommand::new("/sbin/rc-service")
                .arg("cgroups")
                .arg("start"),
            Duration::from_mins(1),
        ),
    };
    // Fixed environment prevents caller-controlled loader/shell behavior in privileged tools.
    command = command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C");
    (command, timeout)
}
async fn run_command(
    step: PreparationStep,
    command: ProcessCommand,
    timeout: Duration,
    cancellation: &Cancellation,
) -> Result<CommandReceipt, PreparationFailure> {
    let (adapter, cleanup) = OwnedProcessAdapter::new(command, std::future::pending());
    let supervisor = Supervisor::new(vec![Registration::new(
        ComponentSpec {
            id: "prerequisite-command".into(),
            prerequisites: vec![],
            kind: ComponentKind::OneShot,
            failure_policy: FailurePolicy::Fatal,
            startup_timeout: timeout,
        },
        adapter,
    )])
    .map_err(|_| PreparationFailure::Graph)?;
    let (handle, receiver) = stop_channel();
    if !cancellation.register(handle) {
        return Err(PreparationFailure::Cancelled);
    }
    let report = supervisor.run(receiver).await;
    let snapshot = cleanup.wait(Duration::from_secs(1)).await;
    let receipt = CommandReceipt {
        step,
        cause: report.cause,
        cleanup: snapshot,
    };
    if !receipt.cleanup_uncertain() {
        cancellation.clear();
    }
    Ok(receipt)
}

/// Install listeners before polling any workflow effects; drive cleanup after cancellation.
/// Requires a Tokio runtime with I/O enabled. Dropping this future is not clean shutdown.
#[cfg(unix)]
pub async fn with_signals<F: Future>(
    cancellation: &Cancellation,
    workflow: F,
) -> std::io::Result<F::Output> {
    drive(cancellation, install_signals(), workflow).await
}
#[cfg(unix)]
struct Signals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}
#[cfg(unix)]
trait Notifications {
    async fn next(&mut self);
}
#[cfg(unix)]
impl Notifications for Signals {
    async fn next(&mut self) {
        tokio::select! {
            biased;
            _ = self.interrupt.recv() => {},
            _ = self.terminate.recv() => {},
        }
    }
}
#[cfg(unix)]
fn install_signals() -> std::io::Result<Signals> {
    use tokio::signal::unix::{SignalKind, signal};
    Ok(Signals {
        interrupt: signal(SignalKind::interrupt())?,
        terminate: signal(SignalKind::terminate())?,
    })
}
#[cfg(unix)]
async fn drive<F: Future>(
    cancellation: &Cancellation,
    notifications: std::io::Result<impl Notifications>,
    workflow: F,
) -> std::io::Result<F::Output> {
    let mut notifications = notifications?;
    tokio::pin!(workflow);
    tokio::select! {
        biased;
        () = notifications.next() => {
            cancellation.cancel();
            // Keep listeners until settled cleanup or the explicit terminal incomplete outcome.
            // Repeated signals are deliberately not polled and cannot restart a deadline.
            Ok(workflow.await)
        },
        result = &mut workflow => Ok(result),
    }
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn missing_executable_is_execution_failure_after_owner_join() {
        let record = CommandReceipt {
            step: PreparationStep::InstallPackages,
            cause: StopCause::Finished,
            cleanup: ProcessCleanupSnapshot {
                started: true,
                thread_finished: true,
                thread_joined: true,
                error: Some("process_spawn_failed"),
                ..Default::default()
            },
        };
        assert!(!record.cleanup_uncertain());
        assert_eq!(
            command_failure(&record, &Cancellation::default()),
            Some(PreparationFailure::Command)
        );
    }
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires disposable Linux fixture"]
    async fn command_deadline_terminates_and_reaps_owned_child() {
        let record = run_command(
            PreparationStep::InstallPackages,
            ProcessCommand::new("/bin/sleep").arg("60"),
            Duration::from_millis(100),
            &Cancellation::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            record.cause,
            StopCause::Fatal(diorama_supervisor::ComponentFailure {
                kind: diorama_supervisor::FailureKind::StartupTimeout,
                ..
            })
        ));
        assert!(
            record.cleanup.spawned
                && record.cleanup.term_attempted
                && record.cleanup.leader_reaped
                && record.cleanup.thread_joined
        );
        assert!(!record.cleanup_uncertain());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn actual_missing_executable_has_no_live_owner() {
        let cancellation = Cancellation::default();
        let record = run_command(
            PreparationStep::InstallPackages,
            ProcessCommand::new(""),
            Duration::from_secs(1),
            &cancellation,
        )
        .await
        .unwrap();
        assert_eq!(record.cleanup.error, Some("process_spawn_failed"));
        assert!(record.cleanup.thread_joined && !record.cleanup.spawned);
        assert_eq!(
            command_failure(&record, &cancellation),
            Some(PreparationFailure::Command)
        );
    }
    struct Immediate;
    impl Notifications for Immediate {
        async fn next(&mut self) {}
    }
    #[tokio::test(flavor = "current_thread")]
    async fn installation_failure_never_polls_workflow() {
        let polled = std::cell::Cell::new(false);
        let result = drive(
            &Cancellation::default(),
            Err::<Immediate, _>(std::io::Error::other("fixture")),
            async {
                polled.set(true);
            },
        )
        .await;
        assert!(result.is_err());
        assert!(!polled.get());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn pending_signal_wins_and_cancellation_prevents_registration() {
        let cancellation = Cancellation::default();
        drive(&cancellation, Ok(Immediate), async {
            assert!(cancellation.is_cancelled());
            assert!(!cancellation.register(stop_channel().0));
        })
        .await
        .unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn active_stop_is_latched_and_bridge_waits_for_cleanup() {
        let cancellation = Cancellation::default();
        let (handle, _) = stop_channel();
        assert!(cancellation.register(handle.clone()));
        drive(&cancellation, Ok(Immediate), async {
            assert!(!handle.stop(), "bridge must already have requested stop");
            tokio::task::yield_now().await;
            cancellation.clear();
            assert!(!cancellation.register(stop_channel().0));
        })
        .await
        .unwrap();
    }
}
