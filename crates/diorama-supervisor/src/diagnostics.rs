//! Latest lifecycle state without a consumer-controlled publication queue.
use crate::{
    CleanupFailure, ComponentFailure, ComponentKind, ComponentState, FailurePolicy, StopCause,
};
use std::fmt;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentDiagnostic {
    /// Public component identity; callers must not put secrets in component IDs.
    pub component: String,
    pub kind: ComponentKind,
    pub failure_policy: FailurePolicy,
    pub state: ComponentState,
    pub state_since: Instant,
    pub startup_deadline: Option<Instant>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleSnapshot {
    pub published_at: Instant,
    pub components: Vec<ComponentDiagnostic>,
    pub cause: Option<StopCause>,
    pub failures: Vec<ComponentFailure>,
    pub cleanup_failures: Vec<CleanupFailure>,
    /// A retained optional failure, even if that component has subsequently stopped.
    pub degraded: bool,
    /// The coordinator produced its final report, not a guarantee of OS cleanup.
    pub finished: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObserverClosed;
impl fmt::Display for ObserverClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("lifecycle publisher closed")
    }
}
impl std::error::Error for ObserverClosed {}

/// Cloning creates another independent cursor over the same latest value.
/// No method exposes a watch borrow guard or holds one across an await.
#[derive(Clone, Debug)]
pub struct LifecycleObserver {
    pub(crate) receiver: watch::Receiver<Arc<LifecycleSnapshot>>,
}
impl LifecycleObserver {
    /// Clone the latest value without marking an update as seen.
    pub fn snapshot(&self) -> Arc<LifecycleSnapshot> {
        Arc::clone(&self.receiver.borrow())
    }
    /// Mark and return the latest unseen value. Intermediate snapshots may coalesce.
    /// A final unseen value is returned before closure. On closure, inspect
    /// `snapshot().finished` to distinguish completion from publisher cancellation.
    pub async fn changed(&mut self) -> Result<Arc<LifecycleSnapshot>, ObserverClosed> {
        self.receiver.changed().await.map_err(|_| ObserverClosed)?;
        Ok(Arc::clone(&self.receiver.borrow_and_update()))
    }
}
