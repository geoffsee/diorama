use crate::diagnostics::{ComponentDiagnostic, LifecycleObserver, LifecycleSnapshot};
use crate::model::{
    Adapter, AdapterContext, AdapterError, CleanupFailure, CleanupKind, ComponentFailure,
    ComponentKind, ComponentOutcome, ComponentSpec, ComponentState, FailureKind, FailurePolicy,
    GRACE_PERIOD, GraphError, Registration, SHUTDOWN_LIMIT, StopCause, StopPhase, StopReceiver,
    SupervisorReport, Transition,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::future::pending;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tokio::task::{AbortHandle, Id, JoinError, JoinSet};
use tokio::time::{Instant, sleep_until};

type Exit = Result<(), AdapterError>;
type Joined = Result<(Id, (usize, Exit, Instant)), JoinError>;
struct Slot {
    spec: ComponentSpec,
    adapter: Option<Box<dyn Adapter>>,
    state: ComponentState,
    state_since: Instant,
    startup_deadline: Option<Instant>,
    cleanup_started: Option<Instant>,
    stop: Option<watch::Sender<StopPhase>>,
    task: Option<AbortHandle>,
    aborted: bool,
}
/// Single coordinator owns task joining. Adapters only report readiness and return outcomes.
pub struct Supervisor {
    slots: Vec<Slot>,
    prerequisites: Vec<Vec<usize>>,
    descendants: Vec<BTreeSet<usize>>,
    order: Vec<usize>,
    tasks: JoinSet<(usize, Exit, Instant)>,
    identities: HashMap<Id, usize>,
    ready_tx: mpsc::UnboundedSender<(usize, Instant)>,
    ready_rx: mpsc::UnboundedReceiver<(usize, Instant)>,
    epoch: Instant,
    stopping: Option<Instant>,
    cause: Option<StopCause>,
    failures: Vec<ComponentFailure>,
    cleanup: Vec<CleanupFailure>,
    transitions: Vec<Transition>,
    diagnostics: Option<watch::Sender<Arc<LifecycleSnapshot>>>,
}
impl fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Supervisor")
            .field("components", &self.slots.len())
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}
fn graph(registrations: &[Registration]) -> Result<(Vec<Vec<usize>>, Vec<usize>), GraphError> {
    let mut ids = BTreeMap::new();
    for (index, registration) in registrations.iter().enumerate() {
        let spec = &registration.spec;
        if spec.id.is_empty() {
            return Err(GraphError::EmptyId);
        }
        if ids.insert(spec.id.clone(), index).is_some() {
            return Err(GraphError::Duplicate(spec.id.clone()));
        }
        if spec.startup_timeout.is_zero() {
            return Err(GraphError::ZeroTimeout(spec.id.clone()));
        }
        if Instant::now().checked_add(spec.startup_timeout).is_none() {
            return Err(GraphError::TimeoutOverflow(spec.id.clone()));
        }
    }
    let mut prerequisites = Vec::new();
    for registration in registrations {
        let mut seen = BTreeSet::new();
        let mut dependencies = Vec::new();
        for id in &registration.spec.prerequisites {
            if !seen.insert(id) {
                return Err(GraphError::DuplicatePrerequisite {
                    component: registration.spec.id.clone(),
                    prerequisite: id.clone(),
                });
            }
            dependencies.push(*ids.get(id).ok_or_else(|| GraphError::Missing {
                component: registration.spec.id.clone(),
                prerequisite: id.clone(),
            })?);
        }
        prerequisites.push(dependencies);
    }
    let mut order = Vec::new();
    let mut visited = BTreeSet::new();
    loop {
        let before = order.len();
        for (index, dependencies) in prerequisites.iter().enumerate() {
            if !visited.contains(&index) && dependencies.iter().all(|id| visited.contains(id)) {
                visited.insert(index);
                order.push(index);
            }
        }
        if order.len() == registrations.len() {
            return Ok((prerequisites, order));
        }
        if order.len() == before {
            return Err(GraphError::Cycle);
        }
    }
}
impl Supervisor {
    /// Validate every dependency before invoking an adapter.
    pub fn new(registrations: Vec<Registration>) -> Result<Self, GraphError> {
        let (prerequisites, order) = graph(&registrations)?;
        let mut descendants = vec![BTreeSet::new(); registrations.len()];
        for &index in order.iter().rev() {
            for &prerequisite in &prerequisites[index] {
                let inherited = descendants[index].clone();
                descendants[prerequisite].insert(index);
                descendants[prerequisite].extend(inherited);
            }
        }
        let (ready_tx, ready_rx) = mpsc::unbounded_channel();
        Ok(Self {
            slots: registrations
                .into_iter()
                .map(|registration| Slot {
                    spec: registration.spec,
                    adapter: Some(registration.adapter),
                    state: ComponentState::Pending,
                    state_since: Instant::now(),
                    startup_deadline: None,
                    cleanup_started: None,
                    stop: None,
                    task: None,
                    aborted: false,
                })
                .collect(),
            prerequisites,
            descendants,
            order,
            tasks: JoinSet::new(),
            identities: HashMap::new(),
            ready_tx,
            ready_rx,
            epoch: Instant::now(),
            stopping: None,
            cause: None,
            failures: Vec::new(),
            cleanup: Vec::new(),
            transitions: Vec::new(),
            diagnostics: None,
        })
    }
    /// Opt into latest-state diagnostics. Repeated calls subscribe to the same publisher.
    /// Consumers cannot backpressure publication or obtain a borrowed channel value.
    pub fn with_observer(mut self) -> (Self, LifecycleObserver) {
        let receiver = if let Some(sender) = &self.diagnostics {
            sender.subscribe()
        } else {
            let (sender, receiver) = watch::channel(Arc::new(self.snapshot(false)));
            self.diagnostics = Some(sender);
            receiver
        };
        (self, LifecycleObserver { receiver })
    }
    fn snapshot(&self, finished: bool) -> LifecycleSnapshot {
        LifecycleSnapshot {
            published_at: Instant::now(),
            components: self
                .slots
                .iter()
                .map(|slot| ComponentDiagnostic {
                    component: slot.spec.id.clone(),
                    kind: slot.spec.kind,
                    failure_policy: slot.spec.failure_policy,
                    state: slot.state,
                    state_since: slot.state_since,
                    startup_deadline: slot.startup_deadline,
                })
                .collect(),
            cause: self.cause.clone(),
            failures: self.failures.clone(),
            cleanup_failures: self.cleanup.clone(),
            degraded: self.failures.iter().any(|failure| {
                self.slots.iter().any(|slot| {
                    slot.spec.id == failure.component
                        && slot.spec.failure_policy == FailurePolicy::Degrade
                })
            }),
            finished,
        }
    }
    fn publish(&self, finished: bool) {
        if let Some(sender) = &self.diagnostics {
            sender.send_replace(Arc::new(self.snapshot(finished)));
        }
    }
    fn transition(&mut self, index: usize, state: ComponentState) {
        if self.slots[index].state != state {
            self.slots[index].state = state;
            self.slots[index].state_since = Instant::now();
            self.transitions.push(Transition {
                component: self.slots[index].spec.id.clone(),
                state,
                elapsed: self.epoch.elapsed(),
            });
        }
    }
    fn begin_stop(&mut self, cause: StopCause) {
        if self.cause.is_none() {
            self.cause = Some(cause);
            self.stopping = Some(Instant::now());
        }
        for index in 0..self.slots.len() {
            if self.slots[index].state == ComponentState::Pending {
                self.transition(index, ComponentState::Stopped);
            }
        }
    }
    fn request_component_stop(&mut self, index: usize) {
        let slot = &mut self.slots[index];
        if slot.task.is_some()
            && slot
                .stop
                .as_ref()
                .is_some_and(|sender| *sender.borrow() == StopPhase::Running)
        {
            slot.cleanup_started.get_or_insert_with(Instant::now);
            slot.startup_deadline = None;
            if let Some(sender) = &slot.stop {
                sender.send_replace(StopPhase::Graceful);
            }
            if slot.state != ComponentState::Failed {
                self.transition(index, ComponentState::Stopping);
            }
        }
    }
    fn fail(&mut self, index: usize, kind: FailureKind) {
        let failure = ComponentFailure {
            component: self.slots[index].spec.id.clone(),
            kind,
        };
        self.failures.push(failure.clone());
        self.slots[index].startup_deadline = None;
        self.transition(index, ComponentState::Failed);
        if self.slots[index].spec.failure_policy == FailurePolicy::Fatal {
            self.begin_stop(StopCause::Fatal(failure));
        } else if self.slots[index].task.is_some() {
            self.slots[index].cleanup_started = Some(Instant::now());
        }
    }
    fn propagate_dependencies(&mut self) {
        for index in self.order.clone() {
            if !matches!(
                self.slots[index].state,
                ComponentState::Pending | ComponentState::Starting | ComponentState::Ready
            ) {
                continue;
            }
            let unavailable = (0..self.slots.len()).find(|&id| {
                self.descendants[id].contains(&index)
                    && matches!(
                        self.slots[id].state,
                        ComponentState::Failed | ComponentState::Blocked
                    )
            });
            if let Some(prerequisite) = unavailable {
                let was_pending = self.slots[index].state == ComponentState::Pending;
                self.fail(
                    index,
                    FailureKind::DependencyFailed(self.slots[prerequisite].spec.id.clone()),
                );
                if was_pending {
                    self.transition(index, ComponentState::Blocked);
                }
            }
        }
    }
    fn start_available(&mut self) {
        if self.stopping.is_some() {
            return;
        }
        for index in self.order.clone() {
            if self.slots[index].state != ComponentState::Pending
                || !self.prerequisites[index].iter().all(|&id| {
                    matches!(
                        self.slots[id].state,
                        ComponentState::Ready | ComponentState::Completed
                    )
                })
            {
                continue;
            }
            let Some(deadline) = Instant::now().checked_add(self.slots[index].spec.startup_timeout)
            else {
                self.fail(index, FailureKind::DeadlineOverflow);
                if self.stopping.is_some() {
                    return;
                }
                continue;
            };
            let Some(adapter) = self.slots[index].adapter.take() else {
                continue;
            };
            let (sender, stop) = watch::channel(StopPhase::Running);
            let context = AdapterContext {
                index,
                ready: Some(self.ready_tx.clone()),
                stop,
            };
            let handle = self.tasks.spawn(async move {
                let outcome = adapter.run(context).await;
                (index, outcome, Instant::now())
            });
            self.identities.insert(handle.id(), index);
            self.slots[index].task = Some(handle);
            self.slots[index].stop = Some(sender);
            self.slots[index].startup_deadline = Some(deadline);
            self.transition(index, ComponentState::Starting);
        }
    }
    fn joined(&mut self, joined: Joined) {
        let (identity, outcome, finished) = match joined {
            Ok((id, (_, outcome, finished))) => (id, Ok(outcome), finished),
            Err(error) => (error.id(), Err(error), Instant::now()),
        };
        let Some(index) = self.identities.remove(&identity) else {
            return;
        };
        let was_stopping = self.slots[index].cleanup_started.is_some() || self.stopping.is_some();
        let expired = self.slots[index]
            .startup_deadline
            .is_some_and(|at| finished >= at);
        self.slots[index].task = None;
        self.slots[index].stop = None;
        self.slots[index].startup_deadline = None;
        if was_stopping {
            let kind = match outcome {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(CleanupKind::Adapter(error.code)),
                Err(error) if error.is_panic() => Some(CleanupKind::Panic),
                Err(_) if self.slots[index].aborted => None,
                Err(_) => Some(CleanupKind::Cancelled),
            };
            if let Some(kind) = kind {
                self.cleanup.push(CleanupFailure {
                    component: self.slots[index].spec.id.clone(),
                    kind,
                });
            }
            if self.slots[index].state != ComponentState::Failed {
                self.transition(index, ComponentState::Stopped);
            }
            return;
        }
        if expired {
            self.fail(index, FailureKind::StartupTimeout);
            let secondary = match outcome {
                Ok(Err(error)) => Some(FailureKind::Adapter(error.code)),
                Err(error) if error.is_panic() => Some(FailureKind::Panic),
                Err(_) => Some(FailureKind::Cancelled),
                Ok(Ok(())) => None,
            };
            if let Some(kind) = secondary {
                self.failures.push(ComponentFailure {
                    component: self.slots[index].spec.id.clone(),
                    kind,
                });
            }
            return;
        }
        match outcome {
            Ok(Ok(())) if self.slots[index].spec.kind == ComponentKind::OneShot => {
                self.transition(index, ComponentState::Completed);
            },
            Ok(Ok(())) => self.fail(index, FailureKind::UnexpectedExit),
            Ok(Err(error)) => self.fail(index, FailureKind::Adapter(error.code)),
            Err(error) if error.is_panic() => self.fail(index, FailureKind::Panic),
            Err(_) => self.fail(index, FailureKind::Cancelled),
        }
    }
    fn stop_waves(&mut self) {
        for index in self.order.clone().into_iter().rev() {
            if self.stopping.is_none() && self.slots[index].cleanup_started.is_none() {
                continue;
            }
            if self.descendants[index]
                .iter()
                .all(|&id| self.slots[id].task.is_none())
            {
                self.request_component_stop(index);
            }
        }
    }
    fn deadlines(&mut self) {
        let now = Instant::now();
        for index in 0..self.slots.len() {
            if self.stopping.is_none()
                && self.slots[index]
                    .startup_deadline
                    .is_some_and(|deadline| now >= deadline)
            {
                self.fail(index, FailureKind::StartupTimeout);
            }
        }
        for index in self.order.clone().into_iter().rev() {
            if self.slots[index].task.is_none() {
                continue;
            }
            let began = match (self.stopping, self.slots[index].cleanup_started) {
                (Some(global), Some(local)) => Some(global.min(local)),
                (global, local) => global.or(local),
            };
            let Some(began) = began else {
                continue;
            };
            if began
                .checked_add(SHUTDOWN_LIMIT)
                .is_none_or(|deadline| now >= deadline)
                && !self.slots[index].aborted
            {
                self.slots[index].aborted = true;
                if let Some(task) = &self.slots[index].task {
                    task.abort();
                }
                self.cleanup.push(CleanupFailure {
                    component: self.slots[index].spec.id.clone(),
                    kind: CleanupKind::AbortedAtDeadline,
                });
            } else if began
                .checked_add(GRACE_PERIOD)
                .is_none_or(|deadline| now >= deadline)
                && self.slots[index]
                    .stop
                    .as_ref()
                    .is_some_and(|sender| *sender.borrow() != StopPhase::Force)
            {
                if let Some(sender) = &self.slots[index].stop {
                    sender.send_replace(StopPhase::Force);
                }
                self.slots[index].cleanup_started.get_or_insert(now);
                self.cleanup.push(CleanupFailure {
                    component: self.slots[index].spec.id.clone(),
                    kind: CleanupKind::Forced,
                });
            }
        }
    }
    fn ready(&mut self, index: usize, at: Instant) {
        if self.stopping.is_none()
            && self.slots[index].state == ComponentState::Starting
            && self.slots[index].spec.kind == ComponentKind::LongRunning
            && self.slots[index]
                .startup_deadline
                .is_some_and(|deadline| at < deadline)
        {
            self.slots[index].startup_deadline = None;
            self.transition(index, ComponentState::Ready);
        }
    }
    fn next_deadline(&self) -> Option<Instant> {
        self.slots
            .iter()
            .filter(|slot| slot.task.is_some() && !slot.aborted)
            .flat_map(|slot| {
                let start = if self.stopping.is_none() {
                    slot.startup_deadline
                } else {
                    None
                };
                let began = match (self.stopping, slot.cleanup_started) {
                    (Some(global), Some(local)) => Some(global.min(local)),
                    (global, local) => global.or(local),
                };
                let cleanup = began.map(|at| {
                    let duration = if slot
                        .stop
                        .as_ref()
                        .is_some_and(|sender| *sender.borrow() == StopPhase::Force)
                    {
                        SHUTDOWN_LIMIT
                    } else {
                        GRACE_PERIOD
                    };
                    at.checked_add(duration).unwrap_or_else(Instant::now)
                });
                [start, cleanup].into_iter().flatten()
            })
            .min()
    }
    /// Run to completion or requested shutdown. Futures must cooperate with Tokio scheduling.
    /// Do not drop this future to request shutdown; use `StopHandle` and await the report.
    pub async fn run(mut self, mut stop: StopReceiver) -> SupervisorReport {
        self.epoch = Instant::now();
        loop {
            // Observe already-completed workers before admitting dependent starts.
            while let Some(joined) = self.tasks.try_join_next_with_id() {
                self.joined(joined);
            }
            if self.stopping.is_none() && *stop.receiver.borrow() {
                self.begin_stop(StopCause::Requested);
            }
            if self.stopping.is_none() && stop.receiver.has_changed().is_err() {
                self.begin_stop(StopCause::ControlClosed);
            }
            while let Ok((index, at)) = self.ready_rx.try_recv() {
                self.ready(index, at);
            }
            self.deadlines();
            self.propagate_dependencies();
            self.stop_waves();
            self.start_available();
            if self.tasks.is_empty()
                && !self
                    .slots
                    .iter()
                    .any(|slot| slot.state == ComponentState::Pending)
            {
                break;
            }
            self.publish(false);
            let deadline = self.next_deadline();
            tokio::select! {
                biased;
                joined = self.tasks.join_next_with_id(), if !self.tasks.is_empty() => {
                    if let Some(joined) = joined { self.joined(joined); }
                }
                _ = stop.receiver.changed(), if self.stopping.is_none() => {}
                () = wait_deadline(deadline) => {}
                Some((index, at)) = self.ready_rx.recv() => { self.ready(index, at); }
            }
        }
        self.cause.get_or_insert(StopCause::Finished);
        self.publish(true);
        SupervisorReport {
            cause: self.cause.unwrap_or(StopCause::Finished),
            outcomes: self
                .slots
                .iter()
                .map(|slot| ComponentOutcome {
                    component: slot.spec.id.clone(),
                    state: slot.state,
                })
                .collect(),
            failures: self.failures,
            cleanup_failures: self.cleanup,
            transitions: self.transitions,
        }
    }
}
async fn wait_deadline(deadline: Option<Instant>) {
    if let Some(deadline) = deadline {
        sleep_until(deadline).await;
    } else {
        pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stop_channel;

    struct Stalled;
    impl Adapter for Stalled {
        fn run(self: Box<Self>, _context: AdapterContext) -> crate::AdapterFuture {
            Box::pin(pending())
        }
    }

    // Find a representable boundary with at most 64 checked additions. Do not move
    // Tokio's clock: enormous virtual advances can overflow unrelated timer internals.
    fn near_instant_limit() -> Instant {
        let now = Instant::now();
        let (mut low, mut high) = (0_u64, u64::MAX);
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if now
                .checked_add(std::time::Duration::from_secs(middle))
                .is_some()
            {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        now.checked_add(std::time::Duration::from_secs(low))
            .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn overflowing_cleanup_deadlines_abort_without_losing_original_cause() {
        let mut supervisor = Supervisor::new(vec![Registration::new(
            ComponentSpec {
                id: "owned".into(),
                prerequisites: vec![],
                kind: ComponentKind::LongRunning,
                failure_policy: FailurePolicy::Fatal,
                startup_timeout: std::time::Duration::from_secs(1),
            },
            Stalled,
        )])
        .unwrap();
        supervisor.start_available();
        let original = ComponentFailure {
            component: "owned".into(),
            kind: FailureKind::Adapter("original_failure"),
        };
        supervisor.failures.push(original.clone());
        supervisor.begin_stop(StopCause::Fatal(original.clone()));
        let boundary = near_instant_limit();
        assert!(boundary.checked_add(GRACE_PERIOD).is_none());
        assert!(boundary.checked_add(SHUTDOWN_LIMIT).is_none());
        supervisor.stopping = Some(boundary);
        assert_eq!(supervisor.next_deadline(), Some(Instant::now()));
        supervisor.slots[0]
            .stop
            .as_ref()
            .unwrap()
            .send_replace(StopPhase::Force);
        assert_eq!(supervisor.next_deadline(), Some(Instant::now()));
        let (_stop, receiver) = stop_channel();
        let report = supervisor.run(receiver).await;
        assert_eq!(report.cause, StopCause::Fatal(original.clone()));
        assert_eq!(report.failures, vec![original]);
        assert!(report.cleanup_failures.iter().any(|failure| {
            failure.component == "owned" && failure.kind == CleanupKind::AbortedAtDeadline
        }));
        assert_eq!(report.outcomes[0].state, ComponentState::Stopped);
    }
}
