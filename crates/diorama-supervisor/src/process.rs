//! Exclusive ownership of a child process group, separate from the async waiter.
use crate::{Adapter, AdapterContext, AdapterError, AdapterFuture, StopPhase};
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};
use std::ffi::OsStr;
use std::fmt;
use std::future::Future;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[path = "process_output.rs"]
mod output;
pub use output::{
    CapturedOutput, InvalidOutputLimit, OutputLimit, OutputSnapshot, OutputStatus, ProcessOutput,
};

const POLL: Duration = Duration::from_millis(10);

/// Command contents are deliberately excluded from diagnostics and Debug.
#[must_use]
pub struct ProcessCommand(Command);
impl fmt::Debug for ProcessCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessCommand(<private command>)")
    }
}
impl ProcessCommand {
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        let mut command = Command::new(program);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Self(command)
    }
    pub fn inherit_stderr(mut self) -> Self {
        self.0.stderr(Stdio::inherit());
        self
    }
    pub fn arg(mut self, value: impl AsRef<OsStr>) -> Self {
        self.0.arg(value);
        self
    }
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.0.env(key, value);
        self
    }
    pub fn env_clear(mut self) -> Self {
        self.0.env_clear();
        self
    }
    pub fn current_dir(mut self, path: impl AsRef<Path>) -> Self {
        self.0.current_dir(path);
        self
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}
/// Facts observed so far, not an assertion that arbitrary descendants are gone.
// These are independent historical facts, not interchangeable control states.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessCleanupSnapshot {
    pub started: bool,
    pub spawned: bool,
    pub term_attempted: bool,
    pub kill_attempted: bool,
    pub force_requested: bool,
    pub leader_reaped: bool,
    pub ownership_lost: bool,
    pub thread_finished: bool,
    pub thread_joined: bool,
    pub exit: Option<ProcessExit>,
    pub error: Option<&'static str>,
}
impl ProcessCleanupSnapshot {
    /// Successful owner completion. This does not prove escaped descendants were contained.
    pub fn complete(&self) -> bool {
        self.started
            && self.thread_joined
            && self.error.is_none()
            && (!self.spawned || self.leader_reaped)
            && !self.ownership_lost
    }
}
#[derive(Default)]
struct Shared {
    snapshot: ProcessCleanupSnapshot,
    thread: Option<JoinHandle<()>>,
    output: Option<Arc<CapturedOutput>>,
}
type State = Arc<Mutex<Shared>>;
fn lock(state: &State) -> MutexGuard<'_, Shared> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
/// An observer never holds a PID or a signaling capability. Keep it after waiter cancellation.
#[derive(Clone)]
pub struct ProcessCleanup(State);
impl fmt::Debug for ProcessCleanup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProcessCleanup")
            .field(&self.snapshot())
            .finish()
    }
}
impl ProcessCleanup {
    pub fn snapshot(&self) -> ProcessCleanupSnapshot {
        let finished = {
            let mut shared = lock(&self.0);
            if shared.thread.as_ref().is_some_and(JoinHandle::is_finished) {
                shared.thread.take()
            } else {
                None
            }
        };
        if let Some(thread) = finished {
            let joined = thread.join(); // is_finished was true; never wait for a running owner here.
            let mut shared = lock(&self.0);
            shared.snapshot.thread_finished = true;
            shared.snapshot.thread_joined = true;
            if joined.is_err() {
                shared.snapshot.error = Some("process_owner_panicked");
            }
        }
        lock(&self.0).snapshot.clone()
    }
    /// Wait up to this observation deadline. Timeout returns an explicitly incomplete snapshot.
    pub async fn wait(&self, timeout: Duration) -> ProcessCleanupSnapshot {
        let Some(deadline) = tokio::time::Instant::now().checked_add(timeout) else {
            return self.snapshot();
        };
        loop {
            let snapshot = self.snapshot();
            if !snapshot.started
                || snapshot.thread_joined
                || tokio::time::Instant::now() >= deadline
            {
                return snapshot;
            }
            tokio::time::sleep_until((tokio::time::Instant::now() + POLL).min(deadline)).await;
        }
    }
}

/// No process/thread/probe is started by this constructor. Launch occurs only when run is polled.
pub struct OwnedProcessAdapter {
    command: ProcessCommand,
    readiness: AdapterFuture,
    cleanup: ProcessCleanup,
    output_limit: Option<OutputLimit>,
}
impl fmt::Debug for OwnedProcessAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedProcessAdapter")
            .field("cleanup", &self.cleanup)
            .finish_non_exhaustive()
    }
}
impl OwnedProcessAdapter {
    pub fn new(
        command: ProcessCommand,
        readiness: impl Future<Output = Result<(), AdapterError>> + Send + 'static,
    ) -> (Self, ProcessCleanup) {
        let cleanup = ProcessCleanup(Arc::new(Mutex::new(Shared::default())));
        (
            Self {
                command,
                readiness: Box::pin(readiness),
                cleanup: cleanup.clone(),
                output_limit: None,
            },
            cleanup,
        )
    }
    /// Capture merged stdout/stderr with a hard retention limit. Default construction stays null.
    pub fn new_with_bounded_output(
        command: ProcessCommand,
        readiness: impl Future<Output = Result<(), AdapterError>> + Send + 'static,
        limit: OutputLimit,
    ) -> (Self, ProcessCleanup, ProcessOutput) {
        let (mut adapter, cleanup) = Self::new(command, readiness);
        adapter.output_limit = Some(limit);
        let output = ProcessOutput(cleanup.clone());
        (adapter, cleanup, output)
    }
}
fn failure(code: &'static str) -> AdapterError {
    AdapterError { code }
}
impl Adapter for OwnedProcessAdapter {
    fn run(self: Box<Self>, context: AdapterContext) -> AdapterFuture {
        Box::pin(run_owned(*self, context))
    }
}
fn outcome(
    snapshot: &ProcessCleanupSnapshot,
    stopping: bool,
    probe_error: Option<&'static str>,
    output_error: Option<&'static str>,
) -> Result<(), AdapterError> {
    if let Some(error) = probe_error.or(snapshot.error).or(output_error) {
        return Err(failure(error));
    }
    let expected_exit = snapshot.exit.is_some_and(|exit| {
        exit.code == Some(0)
            || (stopping
                && ((exit.signal == Some(Signal::TERM.as_raw()) && snapshot.term_attempted)
                    || (exit.signal == Some(Signal::KILL.as_raw()) && snapshot.force_requested)))
    });
    if expected_exit {
        Ok(())
    } else {
        Err(failure("process_exited_unsuccessfully"))
    }
}
async fn run_owned(
    adapter: OwnedProcessAdapter,
    mut context: AdapterContext,
) -> Result<(), AdapterError> {
    let OwnedProcessAdapter {
        command,
        mut readiness,
        cleanup,
        output_limit,
    } = adapter;
    if context.stop_phase() != StopPhase::Running {
        return Ok(());
    }
    let (sender, receiver) = mpsc::channel();
    lock(&cleanup.0).snapshot.started = true;
    let state = cleanup.0.clone();
    let Ok(thread) = thread::Builder::new()
        .name("diorama-process-owner".into())
        .spawn(move || owner(command, &receiver, &state, output_limit))
    else {
        lock(&cleanup.0).snapshot.error = Some("process_owner_spawn_failed");
        return Err(failure("process_owner_spawn_failed"));
    };
    lock(&cleanup.0).thread = Some(thread);
    let mut ready = false;
    let mut stopping = false;
    let mut force_sent = false;
    let mut probe_error = None;
    loop {
        let snapshot = cleanup.snapshot();
        if snapshot.thread_joined {
            let output_error = lock(&cleanup.0)
                .output
                .as_ref()
                .and_then(|output| output.status.error_code());
            return outcome(&snapshot, stopping, probe_error, output_error);
        }
        tokio::select! {
            phase = context.changed(), if !force_sent => {
                if phase != StopPhase::Running {
                    stopping = true;
                    force_sent = phase == StopPhase::Force;
                    let _ = sender.send(phase);
                }
            },
            result = &mut readiness, if snapshot.spawned && snapshot.exit.is_none() && !snapshot.thread_finished
                && snapshot.error.is_none() && !ready && !stopping => {
                ready = true;
                match result {
                    Ok(()) => { context.ready(); },
                    Err(error) => {
                        probe_error = Some(error.code);
                        stopping = true;
                        force_sent = true;
                        let _ = sender.send(StopPhase::Force);
                    }
                }
            },
            () = tokio::time::sleep(POLL) => {},
        }
        // Cancellation drops the sole sender; the owner interprets disconnect as Force.
    }
}

fn retry_interrupted<T>(
    mut operation: impl FnMut() -> rustix::io::Result<T>,
) -> rustix::io::Result<T> {
    loop {
        match operation() {
            Err(rustix::io::Errno::INTR) => {},
            result => return result,
        }
    }
}

struct OwnedChild {
    child: Option<Child>,
    pid: Pid,
    state: State,
    lost: bool,
}
impl OwnedChild {
    fn observe(&mut self) -> Result<bool, &'static str> {
        match retry_interrupted(|| {
            waitid(
                WaitId::Pid(self.pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )
        }) {
            Ok(status) => Ok(status.is_some()),
            Err(rustix::io::Errno::CHILD) => {
                self.lost = true;
                let mut shared = lock(&self.state);
                shared.snapshot.ownership_lost = true;
                shared.snapshot.error = Some("process_child_ownership_lost");
                Err("process_child_ownership_lost")
            },
            Err(_) => Err("process_observation_failed"),
        }
    }
    fn signal(&mut self, signal: Signal) -> Result<(), &'static str> {
        if self.child.is_none() || self.lost || self.pid.is_init() {
            return Err("process_group_not_owned");
        }
        self.observe()?; // No competing reapers/SIGCHLD auto-reap are allowed by the owner contract.
        {
            let mut shared = lock(&self.state);
            if signal == Signal::TERM {
                shared.snapshot.term_attempted = true;
            }
            if signal == Signal::KILL {
                shared.snapshot.kill_attempted = true;
            }
        }
        match kill_process_group(self.pid, signal) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(_) => Err("process_group_signal_failed"),
        }
    }
    fn reap(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        match child.wait() {
            Ok(status) => {
                let mut shared = lock(&self.state);
                shared.snapshot.leader_reaped = true;
                shared.snapshot.exit = Some(ProcessExit {
                    code: status.code(),
                    signal: status.signal(),
                });
            },
            Err(_) => lock(&self.state).snapshot.error = Some("process_reap_failed"),
        }
        // Identity retired permanently. No group signal can follow this final wait.
    }
    fn finish(&mut self) {
        if self.child.is_some() && !self.lost {
            if let Err(error) = self.signal(Signal::KILL) {
                lock(&self.state).snapshot.error = Some(error);
            }
            if !self.lost {
                self.reap();
            }
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Runs on the exclusive owner thread, never the async executor. Kernel wait has no hard bound.
        self.finish();
    }
}
fn owner(
    mut command: ProcessCommand,
    receiver: &mpsc::Receiver<StopPhase>,
    state: &State,
    output_limit: Option<OutputLimit>,
) {
    let Ok(mut drain) = output_limit
        .map(|limit| output::Drain::setup(&mut command, limit))
        .transpose()
    else {
        let mut shared = lock(state);
        shared.output = Some(CapturedOutput::empty(OutputStatus::SetupFailed));
        shared.snapshot.thread_finished = true;
        return;
    };
    command.0.process_group(0);
    let Ok(child) = command.0.spawn() else {
        let mut shared = lock(state);
        shared.snapshot.error = Some("process_spawn_failed");
        if output_limit.is_some() {
            shared.output = Some(CapturedOutput::empty(OutputStatus::SpawnFailed));
        }
        shared.snapshot.thread_finished = true;
        return;
    };
    drop(command); // Close every parent write descriptor; only child stdout/stderr retain writers.
    let pid = Pid::from_child(&child);
    lock(state).snapshot.spawned = true;
    let mut owned = OwnedChild {
        child: Some(child),
        pid,
        state: state.clone(),
        lost: false,
    };
    if pid.is_init() {
        owned.lost = true;
        let mut shared = lock(state);
        shared.snapshot.ownership_lost = true;
        shared.snapshot.error = Some("process_group_pid_one_rejected");
    } else {
        monitor_owned(&mut owned, receiver, state, &mut drain);
    }
    owned.finish();
    drop(owned);
    if let Some(mut output) = drain {
        let began = std::time::Instant::now();
        while output.pending() && began.elapsed() < Duration::from_millis(250) {
            if !matches!(
                receiver.try_recv(),
                Err(mpsc::TryRecvError::Empty) | Ok(StopPhase::Running)
            ) {
                output.cancel();
                break;
            }
            output.turn();
            if output.pending() {
                thread::sleep(POLL);
            }
        }
        lock(state).output = Some(output.publish());
    }
    lock(state).snapshot.thread_finished = true;
}

/// A read-only external service capability: readiness and stop acknowledgement, no process handle.
pub struct ExternalServiceAdapter {
    readiness: AdapterFuture,
}
impl fmt::Debug for ExternalServiceAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExternalServiceAdapter")
    }
}
impl ExternalServiceAdapter {
    pub fn new(readiness: impl Future<Output = Result<(), AdapterError>> + Send + 'static) -> Self {
        Self {
            readiness: Box::pin(readiness),
        }
    }
}
impl Adapter for ExternalServiceAdapter {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            if context.stop_phase() != StopPhase::Running {
                return Ok(());
            }
            let mut readiness = self.readiness;
            tokio::select! {
                result = &mut readiness => { result?; context.ready(); },
                _ = context.changed() => return Ok(()),
            }
            while context.changed().await == StopPhase::Running {}
            Ok(())
        })
    }
}

fn monitor_owned(
    owned: &mut OwnedChild,
    receiver: &mpsc::Receiver<StopPhase>,
    state: &State,
    drain: &mut Option<output::Drain>,
) {
    let mut term = false;
    let mut force = false;
    loop {
        if let Some(output) = drain.as_mut() {
            output.turn();
        }
        if drain.as_ref().is_some_and(output::Drain::failed) && !force {
            force = true;
            lock(state).snapshot.force_requested = true;
            if let Err(error) = owned.signal(Signal::KILL) {
                lock(state).snapshot.error = Some(error);
                break;
            }
        }
        match owned.observe() {
            Ok(true) => break,
            Err(error) => {
                lock(state).snapshot.error = Some(error);
                break;
            },
            Ok(false) => {},
        }
        let phase = if force {
            thread::sleep(POLL);
            StopPhase::Running
        } else {
            match receiver.recv_timeout(POLL) {
                Ok(phase) => phase,
                Err(mpsc::RecvTimeoutError::Disconnected) => StopPhase::Force,
                Err(mpsc::RecvTimeoutError::Timeout) => StopPhase::Running,
            }
        };
        if phase != StopPhase::Running
            && let Some(output) = drain.as_mut()
        {
            output.cancel();
        }
        let signal = match phase {
            StopPhase::Graceful if !term && !force => {
                term = true;
                Some(Signal::TERM)
            },
            StopPhase::Force if !force => {
                force = true;
                lock(state).snapshot.force_requested = true;
                Some(Signal::KILL)
            },
            _ => None,
        };
        if let Some(signal) = signal
            && let Err(error) = owned.signal(signal)
        {
            lock(state).snapshot.error = Some(error);
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ProcessCleanupSnapshot, ProcessExit, outcome, retry_interrupted};
    #[test]
    fn interrupted_observation_retries_without_reporting_process_failure() {
        let mut attempts = 0;
        let result = retry_interrupted(|| {
            attempts += 1;
            if attempts == 1 {
                Err(rustix::io::Errno::INTR)
            } else {
                Ok(false)
            }
        });
        assert_eq!(result, Ok(false));
        assert_eq!(attempts, 2);
    }
    #[test]
    fn requested_stop_does_not_hide_abnormal_exit() {
        let snapshot = ProcessCleanupSnapshot {
            term_attempted: true,
            exit: Some(ProcessExit {
                code: Some(17),
                signal: None,
            }),
            ..Default::default()
        };
        assert_eq!(
            outcome(&snapshot, true, None, None)
                .expect_err("abnormal exit")
                .code,
            "process_exited_unsuccessfully"
        );
    }
    #[test]
    fn cleanup_error_does_not_replace_primary_readiness_failure() {
        let snapshot = ProcessCleanupSnapshot {
            error: Some("cleanup_failed"),
            ..Default::default()
        };
        assert_eq!(
            outcome(
                &snapshot,
                true,
                Some("probe_failed"),
                Some("process_output_incomplete")
            )
            .expect_err("primary failure")
            .code,
            "probe_failed"
        );
        assert_eq!(snapshot.error, Some("cleanup_failed"));
    }
    #[test]
    fn output_failure_does_not_hide_ownership_or_signal_failure() {
        for error in [
            "process_child_ownership_lost",
            "process_group_signal_failed",
        ] {
            let snapshot = ProcessCleanupSnapshot {
                error: Some(error),
                ..Default::default()
            };
            for output in ["process_output_incomplete", "process_output_limit"] {
                assert_eq!(
                    outcome(&snapshot, true, None, Some(output))
                        .expect_err("owner failure")
                        .code,
                    error
                );
            }
        }
        assert_eq!(
            outcome(
                &ProcessCleanupSnapshot::default(),
                false,
                None,
                Some("process_output_incomplete")
            )
            .expect_err("output failure")
            .code,
            "process_output_incomplete"
        );
    }
}
