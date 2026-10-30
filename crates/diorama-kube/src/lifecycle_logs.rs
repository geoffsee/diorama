//! Opt-in lifecycle JSONL rendering and bounded delivery; no global output sink.
use diorama_supervisor::{
    CleanupKind, ComponentDiagnostic, ComponentFailure, ComponentKind, ComponentState, FailureKind,
    FailurePolicy, LifecycleObserver, LifecycleSnapshot, StopCause,
};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::Instant;

pub const MAX_COMPONENTS: usize = 256;
pub const MAX_DIAGNOSTICS: usize = 1024;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_FRAME_BYTES: usize = 4096;
pub const MAX_BATCH_BYTES: usize = 65_536;
pub const MAX_QUEUE_CAPACITY: usize = 64;

/// A threshold includes its own level and all more severe levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}
impl LogLevel {
    fn name(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
    pub fn from_debug(debug: bool) -> Self {
        if debug { Self::Debug } else { Self::Info }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderError {
    InputLimit,
    InvalidSnapshot,
    GraphChanged,
    HistoryChanged,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelCapacityError;
impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InputLimit => "lifecycle diagnostic input exceeds limits",
            Self::InvalidSnapshot => "invalid lifecycle diagnostic snapshot",
            Self::GraphChanged => "lifecycle diagnostic graph changed",
            Self::HistoryChanged => "lifecycle diagnostic history changed",
        })
    }
}
impl std::error::Error for RenderError {}
impl std::fmt::Display for ChannelCapacityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("lifecycle log capacity must be between 1 and 64")
    }
}
impl std::error::Error for ChannelCapacityError {}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogFrame(String);
impl LogFrame {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Debug, Default)]
pub struct RenderedBatch {
    pub frames: Vec<LogFrame>,
    pub filtered: u64,
    pub oversize: u64,
    bytes: usize,
}
impl RenderedBatch {
    fn record(
        &mut self,
        threshold: LogLevel,
        level: LogLevel,
        event: &'static str,
        mut fields: Value,
    ) {
        if level > threshold {
            self.filtered += 1;
            return;
        }
        fields["schema"] = 1.into();
        fields["level"] = level.name().into();
        fields["event"] = event.into();
        sort_json_keys(&mut fields);
        let mut line = fields.to_string();
        line.push('\n');
        if line.len() > MAX_FRAME_BYTES || line.len() > MAX_BATCH_BYTES - self.bytes {
            self.oversize += 1;
        } else {
            self.bytes += line.len();
            self.frames.push(LogFrame(line));
        }
    }
}

fn sort_json_keys(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<String, Value> =
                std::mem::take(map).into_iter().collect();
            for (k, mut v) in sorted {
                sort_json_keys(&mut v);
                map.insert(k, v);
            }
        },
        Value::Array(items) => {
            for item in items {
                sort_json_keys(item);
            }
        },
        _ => {},
    }
}

/// Stateful deduplication for one immutable registered graph. Create a fresh
/// renderer for a different supervisor. IDs and codes must be public identifiers.
#[derive(Debug)]
pub struct LifecycleRenderer {
    level: LogLevel,
    previous: Option<LifecycleSnapshot>,
}
impl LifecycleRenderer {
    pub fn new(level: LogLevel) -> Self {
        Self {
            level,
            previous: None,
        }
    }
    /// Deterministic for the supplied snapshots; no clock, environment or I/O reads.
    pub fn render(&mut self, snapshot: &LifecycleSnapshot) -> Result<RenderedBatch, RenderError> {
        validate(snapshot)?;
        let previous = self.previous.as_ref();
        if let Some(old) = previous {
            validate_history(old, snapshot)?;
        }
        let mut batch = RenderedBatch::default();
        let prior_failures = previous.map_or(0, |old| old.failures.len());
        for failure in &snapshot.failures[prior_failures..] {
            batch.record(
                self.level,
                LogLevel::Error,
                "component_failure",
                failure_fields(failure),
            );
        }
        let prior_cleanup = previous.map_or(0, |old| old.cleanup_failures.len());
        for failure in &snapshot.cleanup_failures[prior_cleanup..] {
            let (code, detail, level) = cleanup_code(&failure.kind);
            batch.record(
                self.level,
                level,
                "component_cleanup",
                json!({"component":failure.component,"code":code,"detail_code":detail}),
            );
        }
        if snapshot.cause.is_some() && previous.is_none_or(|old| old.cause != snapshot.cause) {
            let (level, fields) = cause_fields(
                snapshot
                    .cause
                    .as_ref()
                    .ok_or(RenderError::InvalidSnapshot)?,
            );
            batch.record(self.level, level, "supervisor_stop", fields);
        }
        if snapshot.degraded && previous.is_none_or(|old| !old.degraded) {
            batch.record(
                self.level,
                LogLevel::Info,
                "supervisor_degraded",
                json!({"degraded":true}),
            );
        }
        if snapshot.finished && previous.is_none_or(|old| !old.finished) {
            batch.record(
                self.level,
                LogLevel::Info,
                "supervisor_finished",
                json!({"finished":true,"degraded":snapshot.degraded}),
            );
        }
        for (index, component) in snapshot.components.iter().enumerate() {
            if previous.is_none_or(|old| old.components[index] != *component) {
                batch.record(
                    self.level,
                    LogLevel::Debug,
                    "component_state",
                    component_fields(component, snapshot.published_at),
                );
            }
        }
        self.previous = Some(snapshot.clone());
        Ok(batch)
    }
}
fn bounded(value: &str) -> bool {
    value.len() <= MAX_IDENTIFIER_BYTES
}
fn failure_code(kind: &FailureKind) -> (&'static str, Option<&str>) {
    match kind {
        FailureKind::Adapter(code) => ("adapter", Some(code)),
        FailureKind::DependencyFailed(component) => ("dependency_failed", Some(component)),
        FailureKind::UnexpectedExit => ("unexpected_exit", None),
        FailureKind::StartupTimeout => ("startup_timeout", None),
        FailureKind::DeadlineOverflow => ("deadline_overflow", None),
        FailureKind::Panic => ("panic", None),
        FailureKind::Cancelled => ("cancelled", None),
    }
}
fn cleanup_code(kind: &CleanupKind) -> (&'static str, Option<&str>, LogLevel) {
    match kind {
        CleanupKind::Adapter(code) => ("adapter", Some(code), LogLevel::Error),
        CleanupKind::Panic => ("panic", None, LogLevel::Error),
        CleanupKind::Forced => ("forced", None, LogLevel::Warn),
        CleanupKind::AbortedAtDeadline => ("aborted_at_deadline", None, LogLevel::Error),
        CleanupKind::Cancelled => ("cancelled", None, LogLevel::Error),
    }
}
fn validate(snapshot: &LifecycleSnapshot) -> Result<(), RenderError> {
    if snapshot.components.len() > MAX_COMPONENTS
        || snapshot.failures.len() > MAX_DIAGNOSTICS
        || snapshot.cleanup_failures.len() > MAX_DIAGNOSTICS - snapshot.failures.len()
    {
        return Err(RenderError::InputLimit);
    }
    for (index, component) in snapshot.components.iter().enumerate() {
        if !bounded(&component.component) {
            return Err(RenderError::InputLimit);
        }
        if component.component.is_empty()
            || component.state_since > snapshot.published_at
            || snapshot.components[..index]
                .iter()
                .any(|c| c.component == component.component)
        {
            return Err(RenderError::InvalidSnapshot);
        }
    }
    let known = |id: &str| snapshot.components.iter().any(|c| c.component == id);
    for failure in &snapshot.failures {
        let (_, detail) = failure_code(&failure.kind);
        if !bounded(&failure.component) || detail.is_some_and(|value| !bounded(value)) {
            return Err(RenderError::InputLimit);
        }
        if !known(&failure.component)
            || matches!(&failure.kind, FailureKind::DependencyFailed(id) if !known(id))
        {
            return Err(RenderError::InvalidSnapshot);
        }
    }
    for failure in &snapshot.cleanup_failures {
        let (_, detail, _) = cleanup_code(&failure.kind);
        if !bounded(&failure.component) || detail.is_some_and(|value| !bounded(value)) {
            return Err(RenderError::InputLimit);
        }
        if !known(&failure.component) {
            return Err(RenderError::InvalidSnapshot);
        }
    }
    if let Some(StopCause::Fatal(failure)) = &snapshot.cause
        && !snapshot.failures.contains(failure)
    {
        return Err(RenderError::InvalidSnapshot);
    }
    let degraded = snapshot.failures.iter().any(|failure| {
        snapshot
            .components
            .iter()
            .any(|c| c.component == failure.component && c.failure_policy == FailurePolicy::Degrade)
    });
    if snapshot.degraded != degraded || (snapshot.finished && snapshot.cause.is_none()) {
        return Err(RenderError::InvalidSnapshot);
    }
    Ok(())
}
fn validate_history(old: &LifecycleSnapshot, new: &LifecycleSnapshot) -> Result<(), RenderError> {
    if old.components.len() != new.components.len()
        || old.components.iter().zip(&new.components).any(|(a, b)| {
            a.component != b.component || a.kind != b.kind || a.failure_policy != b.failure_policy
        })
    {
        return Err(RenderError::GraphChanged);
    }
    if !new.failures.starts_with(&old.failures)
        || !new.cleanup_failures.starts_with(&old.cleanup_failures)
        || old
            .cause
            .as_ref()
            .is_some_and(|cause| Some(cause) != new.cause.as_ref())
        || new.published_at < old.published_at
        || (old.finished && old != new)
    {
        return Err(RenderError::HistoryChanged);
    }
    Ok(())
}
fn state_name(state: ComponentState) -> &'static str {
    match state {
        ComponentState::Pending => "pending",
        ComponentState::Starting => "starting",
        ComponentState::Ready => "ready",
        ComponentState::Completed => "completed",
        ComponentState::Failed => "failed",
        ComponentState::Blocked => "blocked",
        ComponentState::Stopping => "stopping",
        ComponentState::Stopped => "stopped",
    }
}
fn component_fields(component: &ComponentDiagnostic, at: Instant) -> Value {
    json!({"component":component.component,"state":state_name(component.state),
        "kind":match component.kind { ComponentKind::OneShot=>"one_shot",ComponentKind::LongRunning=>"long_running" },
        "policy":match component.failure_policy { FailurePolicy::Fatal=>"fatal",FailurePolicy::Degrade=>"degrade" },
        "state_age_ms":u64::try_from(at.duration_since(component.state_since).as_millis()).unwrap_or(u64::MAX),
        "startup_remaining_ms":component.startup_deadline.map(|deadline|u64::try_from(deadline.saturating_duration_since(at).as_millis()).unwrap_or(u64::MAX))})
}
fn failure_fields(failure: &ComponentFailure) -> Value {
    let (code, detail) = failure_code(&failure.kind);
    json!({"component":failure.component,"code":code,"detail_code":detail})
}
fn cause_fields(cause: &StopCause) -> (LogLevel, Value) {
    match cause {
        StopCause::Fatal(failure) => (LogLevel::Error, failure_fields(failure)),
        StopCause::Requested => (LogLevel::Info, json!({"code":"requested"})),
        StopCause::ControlClosed => (LogLevel::Warn, json!({"code":"control_closed"})),
        StopCause::Finished => (LogLevel::Info, json!({"code":"finished"})),
    }
}

#[derive(Clone, Debug)]
pub struct LogSender(mpsc::Sender<LogFrame>);
#[derive(Debug)]
pub struct LogReceiver(mpsc::Receiver<LogFrame>);
impl LogReceiver {
    pub async fn recv(&mut self) -> Option<LogFrame> {
        self.0.recv().await
    }

    /// Blocks this thread until a frame arrives or the sender is dropped.
    /// Call it from `deliver_logs`'s blocking worker, not from an async runtime worker.
    pub fn blocking_recv(&mut self) -> Option<LogFrame> {
        self.0.blocking_recv()
    }
}
pub fn log_channel(capacity: usize) -> Result<(LogSender, LogReceiver), ChannelCapacityError> {
    if !(1..=MAX_QUEUE_CAPACITY).contains(&capacity) {
        return Err(ChannelCapacityError);
    }
    let (sender, receiver) = mpsc::channel(capacity);
    Ok((LogSender(sender), LogReceiver(receiver)))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublisherStatus {
    Open,
    Finished,
    Cancelled,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryReport {
    pub filtered: u64,
    pub enqueued: u64,
    pub dropped_full: u64,
    pub oversize: u64,
    pub closed: u64,
    pub publisher: PublisherStatus,
    pub render_error: Option<RenderError>,
}
impl Default for DeliveryReport {
    fn default() -> Self {
        Self {
            filtered: 0,
            enqueued: 0,
            dropped_full: 0,
            oversize: 0,
            closed: 0,
            publisher: PublisherStatus::Open,
            render_error: None,
        }
    }
}
/// Caller owns/spawns this future and the receiver. Never writes to an OS sink.
/// Full queues lose frames explicitly; they never backpressure supervision.
/// Enqueued does not mean flushed or acknowledged by a downstream writer.
pub async fn consume_lifecycle(
    mut observer: LifecycleObserver,
    mut renderer: LifecycleRenderer,
    sender: LogSender,
) -> DeliveryReport {
    let mut report = DeliveryReport::default();
    loop {
        let snapshot = observer.snapshot();
        if snapshot.finished {
            report.publisher = PublisherStatus::Finished;
        }
        let batch = match renderer.render(&snapshot) {
            Ok(batch) => batch,
            Err(error) => {
                report.render_error = Some(error);
                return report;
            },
        };
        report.filtered = report.filtered.saturating_add(batch.filtered);
        report.oversize = report.oversize.saturating_add(batch.oversize);
        let count = batch.frames.len();
        for (index, frame) in batch.frames.into_iter().enumerate() {
            match sender.0.try_send(frame) {
                Ok(()) => report.enqueued = report.enqueued.saturating_add(1),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    report.dropped_full = report.dropped_full.saturating_add(1);
                },
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    report.closed = report
                        .closed
                        .saturating_add(u64::try_from(count - index).unwrap_or(u64::MAX));
                    return report;
                },
            }
        }
        if report.publisher == PublisherStatus::Finished {
            return report;
        }
        tokio::select! {
            result = observer.changed() => if result.is_err() { report.publisher = PublisherStatus::Cancelled; return report; },
            () = sender.0.closed() => { report.closed = report.closed.saturating_add(1); return report; },
        }
    }
}
