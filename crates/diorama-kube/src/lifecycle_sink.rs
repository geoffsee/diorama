//! Caller-owned delivery of already rendered lifecycle frames.
//!
//! This module does not render, filter, subscribe, or start a supervisor. The caller
//! retains `consume_lifecycle` and chooses when to spawn `deliver_logs`.

use std::io::{self, Write};

use diorama_config::ValidatedConfig;

use crate::lifecycle_logs::{LogLevel, LogReceiver};

/// When accepted frames are flushed to the caller-owned writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushPolicy {
    /// Flush after every successful frame write.
    EachFrame,
    /// Write every frame, then flush once when the sender closes, even if none arrived.
    OnClose,
}

/// Terminal result of one delivery attempt. IO details are only `ErrorKind` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkOutcome {
    /// The sender closed and every required flush succeeded.
    Closed,
    /// `write_all` failed. Later frames were not attempted.
    Write(io::ErrorKind),
    /// A required flush failed. That frame is counted as written and not flushed.
    Flush(io::ErrorKind),
    /// The blocking worker panicked or was cancelled. Counts from that attempt are discarded.
    WorkerLost,
}

/// Frames accepted by `write_all`, frames covered by a successful required flush,
/// and why delivery stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SinkReport {
    pub written: u64,
    pub flushed_frames: u64,
    pub outcome: SinkOutcome,
}

/// Level selected by the resolved `logging.debug` setting.
pub fn configured_log_level(config: &ValidatedConfig) -> LogLevel {
    LogLevel::from_debug(config.config().logging.debug)
}

/// Write frames on a dedicated blocking worker until the sender closes or a required IO call fails.
///
/// The returned future must be polled on a Tokio runtime. Dropping it detaches that worker:
/// delivery continues until the sender closes, the final `OnClose` flush still runs, and this
/// call does not return its report. A slow writer cannot stall supervision because the renderer
/// uses a bounded non-blocking queue. Accepted bytes can still sit in a buffered writer until
/// the policy flushes them. This function does not redact frame contents.
pub async fn deliver_logs<W>(receiver: LogReceiver, writer: W, policy: FlushPolicy) -> SinkReport
where
    W: Write + Send + 'static,
{
    match tokio::task::spawn_blocking(move || transfer(receiver, writer, policy)).await {
        Ok(report) => report,
        Err(_) => SinkReport {
            written: 0,
            flushed_frames: 0,
            outcome: SinkOutcome::WorkerLost,
        },
    }
}

fn transfer<W: Write>(mut receiver: LogReceiver, mut writer: W, policy: FlushPolicy) -> SinkReport {
    let mut written = 0_u64;
    let mut flushed_frames = 0_u64;
    let mut pending = 0_u64;
    loop {
        if let Some(frame) = receiver.blocking_recv() {
            if let Err(error) = writer.write_all(frame.as_str().as_bytes()) {
                return report(written, flushed_frames, SinkOutcome::Write(error.kind()));
            }
            written = written.saturating_add(1);
            pending = pending.saturating_add(1);
            if policy == FlushPolicy::EachFrame
                && let Err(outcome) = flush_pending(&mut writer, &mut flushed_frames, &mut pending)
            {
                return report(written, flushed_frames, outcome);
            }
        } else {
            if (policy == FlushPolicy::OnClose || pending > 0)
                && let Err(outcome) = flush_pending(&mut writer, &mut flushed_frames, &mut pending)
            {
                return report(written, flushed_frames, outcome);
            }
            return report(written, flushed_frames, SinkOutcome::Closed);
        }
    }
}

fn flush_pending<W: Write>(
    writer: &mut W,
    flushed_frames: &mut u64,
    pending: &mut u64,
) -> Result<(), SinkOutcome> {
    if let Err(error) = writer.flush() {
        return Err(SinkOutcome::Flush(error.kind()));
    }
    *flushed_frames = flushed_frames.saturating_add(*pending);
    *pending = 0;
    Ok(())
}

fn report(written: u64, flushed_frames: u64, outcome: SinkOutcome) -> SinkReport {
    SinkReport {
        written,
        flushed_frames,
        outcome,
    }
}
