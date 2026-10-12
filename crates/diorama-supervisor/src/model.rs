use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

pub const GRACE_PERIOD: Duration = Duration::from_secs(30);
pub const SHUTDOWN_LIMIT: Duration = Duration::from_secs(35);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentKind {
    OneShot,
    LongRunning,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailurePolicy {
    Fatal,
    Degrade,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentSpec {
    pub id: String,
    pub prerequisites: Vec<String>,
    pub kind: ComponentKind,
    pub failure_policy: FailurePolicy,
    pub startup_timeout: Duration,
}
pub type AdapterFuture = Pin<Box<dyn Future<Output = Result<(), AdapterError>> + Send + 'static>>;
/// An adapter must remain cooperatively pollable and clean up before returning.
/// Returning success from a long-running adapter before stop is unexpected exit.
pub trait Adapter: Send + 'static {
    fn run(self: Box<Self>, context: AdapterContext) -> AdapterFuture;
}
/// Use a static diagnostic code, never credentials, raw command lines, or environment values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterError {
    pub code: &'static str,
}
impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for AdapterError {}

pub struct Registration {
    pub spec: ComponentSpec,
    pub(crate) adapter: Box<dyn Adapter>,
}
impl Registration {
    pub fn new(spec: ComponentSpec, adapter: impl Adapter) -> Self {
        Self {
            spec,
            adapter: Box::new(adapter),
        }
    }
}
impl fmt::Debug for Registration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registration")
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphError {
    Duplicate(String),
    Missing {
        component: String,
        prerequisite: String,
    },
    DuplicatePrerequisite {
        component: String,
        prerequisite: String,
    },
    EmptyId,
    ZeroTimeout(String),
    TimeoutOverflow(String),
    Cycle,
}
impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid component graph: {self:?}")
    }
}
impl std::error::Error for GraphError {}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopPhase {
    Running,
    Graceful,
    Force,
}
#[derive(Debug)]
pub struct AdapterContext {
    pub(crate) index: usize,
    pub(crate) ready: Option<mpsc::UnboundedSender<(usize, tokio::time::Instant)>>,
    pub(crate) stop: watch::Receiver<StopPhase>,
}
impl AdapterContext {
    /// Report usable readiness once. One-shot dependencies become usable only after completion.
    pub fn ready(&mut self) -> bool {
        self.ready.take().is_some_and(|sender| {
            sender
                .send((self.index, tokio::time::Instant::now()))
                .is_ok()
        })
    }
    pub fn stop_phase(&self) -> StopPhase {
        if self.stop.has_changed().is_err() {
            StopPhase::Force
        } else {
            *self.stop.borrow()
        }
    }
    /// Wait for the next stop phase. Coordinator disappearance requests forced cleanup.
    pub async fn changed(&mut self) -> StopPhase {
        if self.stop.changed().await.is_err() {
            return StopPhase::Force;
        }
        self.stop_phase()
    }
}
#[derive(Clone, Debug)]
pub struct StopHandle {
    sender: watch::Sender<bool>,
}
#[derive(Debug)]
pub struct StopReceiver {
    pub(crate) receiver: watch::Receiver<bool>,
}
pub fn stop_channel() -> (StopHandle, StopReceiver) {
    let (sender, receiver) = watch::channel(false);
    (StopHandle { sender }, StopReceiver { receiver })
}
impl StopHandle {
    /// Returns true only for the first request. Dropping all handles also requests shutdown.
    pub fn stop(&self) -> bool {
        !self.sender.send_replace(true)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentState {
    Pending,
    Starting,
    Ready,
    Completed,
    Failed,
    Blocked,
    Stopping,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailureKind {
    Adapter(&'static str),
    UnexpectedExit,
    StartupTimeout,
    DeadlineOverflow,
    DependencyFailed(String),
    Panic,
    Cancelled,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentFailure {
    pub component: String,
    pub kind: FailureKind,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopCause {
    Requested,
    ControlClosed,
    Fatal(ComponentFailure),
    Finished,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub component: String,
    pub state: ComponentState,
    pub elapsed: Duration,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CleanupKind {
    Adapter(&'static str),
    Panic,
    Forced,
    AbortedAtDeadline,
    Cancelled,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupFailure {
    pub component: String,
    pub kind: CleanupKind,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentOutcome {
    pub component: String,
    pub state: ComponentState,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisorReport {
    pub cause: StopCause,
    pub outcomes: Vec<ComponentOutcome>,
    pub failures: Vec<ComponentFailure>,
    pub cleanup_failures: Vec<CleanupFailure>,
    pub transitions: Vec<Transition>,
}
