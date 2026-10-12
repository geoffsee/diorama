//! Bounded merged output, drained by the existing process owner only.
use super::{ProcessCleanup, ProcessCommand};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use std::fmt;
use std::io::pipe;
use std::os::fd::OwnedFd;
use std::process::Stdio;
use std::sync::Arc;

/// Maximum retained bytes. Validation occurs before any process or pipe exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputLimit(usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidOutputLimit;
impl fmt::Display for InvalidOutputLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("output limit must be between 1 and 65536 bytes")
    }
}
impl std::error::Error for InvalidOutputLimit {}
impl OutputLimit {
    pub fn new(bytes: usize) -> Result<Self, InvalidOutputLimit> {
        if (1..=65_536).contains(&bytes) {
            Ok(Self(bytes))
        } else {
            Err(InvalidOutputLimit)
        }
    }
    pub fn bytes(self) -> usize {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputStatus {
    Complete,
    LimitExceeded,
    ReadFailed,
    Cancelled,
    IncompleteAfterExit,
    SetupFailed,
    SpawnFailed,
    OwnerFailed,
}
impl OutputStatus {
    pub(super) fn error_code(self) -> Option<&'static str> {
        match self {
            Self::Complete | Self::Cancelled => None,
            Self::LimitExceeded => Some("process_output_limit"),
            Self::ReadFailed => Some("process_output_read_failed"),
            Self::IncompleteAfterExit => Some("process_output_incomplete"),
            Self::SetupFailed => Some("process_output_setup_failed"),
            Self::SpawnFailed => Some("process_spawn_failed"),
            Self::OwnerFailed => Some("process_output_owner_failed"),
        }
    }
}
/// Raw bytes are explicit opt-in data; they are never included in Debug or errors.
#[derive(Clone, PartialEq, Eq)]
pub struct CapturedOutput {
    pub status: OutputStatus,
    bytes: Vec<u8>,
}
impl CapturedOutput {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn empty(status: OutputStatus) -> Arc<Self> {
        Arc::new(Self {
            status,
            bytes: vec![],
        })
    }
}
impl fmt::Debug for CapturedOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedOutput")
            .field("status", &self.status)
            .field("retained_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputSnapshot {
    NotStarted,
    Running,
    Finished(Arc<CapturedOutput>),
}
/// Contains neither a process identity nor a signaling capability.
#[derive(Clone)]
pub struct ProcessOutput(pub(super) ProcessCleanup);
impl fmt::Debug for ProcessOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProcessOutput")
            .field(&self.snapshot())
            .finish()
    }
}
impl ProcessOutput {
    pub fn snapshot(&self) -> OutputSnapshot {
        let cleanup = self.0.snapshot();
        let shared = super::lock(&self.0.0);
        if let Some(output) = &shared.output {
            return OutputSnapshot::Finished(output.clone());
        }
        if !cleanup.started {
            return OutputSnapshot::NotStarted;
        }
        if cleanup.thread_joined || cleanup.error == Some("process_owner_spawn_failed") {
            return OutputSnapshot::Finished(CapturedOutput::empty(OutputStatus::OwnerFailed));
        }
        OutputSnapshot::Running
    }
}

pub(super) struct Drain {
    reader: Option<OwnedFd>,
    bytes: Vec<u8>,
    limit: OutputLimit,
    status: Option<OutputStatus>,
}
impl Drain {
    pub(super) fn setup(command: &mut ProcessCommand, limit: OutputLimit) -> Result<Self, ()> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(limit.bytes()).map_err(|_| ())?;
        let (reader, writer) = pipe().map_err(|_| ())?;
        let flags = fcntl_getfl(&reader).map_err(|_| ())?;
        fcntl_setfl(&reader, flags | OFlags::NONBLOCK).map_err(|_| ())?;
        let stderr = writer.try_clone().map_err(|_| ())?;
        command
            .0
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(stderr));
        Ok(Self {
            reader: Some(reader.into()),
            bytes,
            limit,
            status: None,
        })
    }
    /// At most four bounded reads per owner turn; even EINTR consumes one attempt.
    pub(super) fn turn(&mut self) {
        let mut scratch = [0_u8; 1024];
        for _ in 0..4 {
            let Some(reader) = &self.reader else {
                return;
            };
            let remaining = self.limit.bytes() - self.bytes.len();
            let cancelled = self.status == Some(OutputStatus::Cancelled);
            let size = if cancelled {
                scratch.len()
            } else {
                scratch.len().min(remaining + 1)
            };
            match rustix::io::read(reader, &mut scratch[..size]) {
                Ok(0) => {
                    self.finish(if cancelled {
                        OutputStatus::Cancelled
                    } else {
                        OutputStatus::Complete
                    });
                    return;
                },
                Ok(_) if cancelled => {},
                Ok(count) => {
                    self.bytes
                        .extend_from_slice(&scratch[..count.min(remaining)]);
                    if count > remaining {
                        self.finish(OutputStatus::LimitExceeded);
                        return;
                    }
                },
                Err(rustix::io::Errno::INTR) => {},
                Err(rustix::io::Errno::AGAIN) => return,
                Err(_) => {
                    self.finish(if cancelled {
                        OutputStatus::Cancelled
                    } else {
                        OutputStatus::ReadFailed
                    });
                    return;
                },
            }
        }
    }
    fn finish(&mut self, status: OutputStatus) {
        self.status = Some(status);
        self.reader.take();
    }
    pub(super) fn cancel(&mut self) {
        if matches!(self.status, None | Some(OutputStatus::Complete)) {
            self.status = Some(OutputStatus::Cancelled);
        }
    }
    pub(super) fn failed(&self) -> bool {
        self.status
            .is_some_and(|status| status.error_code().is_some())
    }
    pub(super) fn pending(&self) -> bool {
        self.reader.is_some()
    }
    pub(super) fn publish(mut self) -> Arc<CapturedOutput> {
        if self.status.is_none() {
            self.finish(OutputStatus::IncompleteAfterExit);
        }
        Arc::new(CapturedOutput {
            status: self.status.unwrap_or(OutputStatus::IncompleteAfterExit),
            bytes: self.bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn local_pipe(limit: usize) -> (Drain, std::io::PipeWriter) {
        let (reader, writer) = pipe().unwrap();
        fcntl_setfl(&reader, fcntl_getfl(&reader).unwrap() | OFlags::NONBLOCK).unwrap();
        (
            Drain {
                reader: Some(reader.into()),
                bytes: Vec::with_capacity(limit),
                limit: OutputLimit::new(limit).unwrap(),
                status: None,
            },
            writer,
        )
    }
    #[test]
    fn limits_reject_zero_and_over_budget_before_effects() {
        assert!(OutputLimit::new(0).is_err());
        assert!(OutputLimit::new(65_537).is_err());
        assert_eq!(OutputLimit::new(1).unwrap().bytes(), 1);
        assert_eq!(OutputLimit::new(65_536).unwrap().bytes(), 65_536);
    }
    #[test]
    fn exact_limit_requires_eof_and_extra_byte_fails() {
        let (mut drain, mut writer) = local_pipe(4);
        writer.write_all(b"abcd").unwrap();
        drain.turn();
        assert!(drain.pending());
        assert_eq!(drain.bytes, b"abcd");
        drop(writer);
        drain.turn();
        assert_eq!(drain.publish().status, OutputStatus::Complete);
        let (mut drain, mut writer) = local_pipe(4);
        writer.write_all(b"abcde").unwrap();
        drain.turn();
        assert!(drain.failed());
        let result = drain.publish();
        assert_eq!(result.status, OutputStatus::LimitExceeded);
        assert_eq!(result.bytes(), b"abcd");
    }
    #[test]
    fn retained_writer_never_blocks_and_unfinished_output_is_explicit() {
        let (mut drain, _writer) = local_pipe(4);
        drain.turn();
        assert!(drain.pending());
        assert_eq!(drain.publish().status, OutputStatus::IncompleteAfterExit);
    }
    #[test]
    fn cancellation_discards_without_closing_writer_or_retaining_more_bytes() {
        let (mut drain, mut writer) = local_pipe(32);
        writer.write_all(b"private-version").unwrap();
        drain.turn();
        drain.cancel();
        assert!(drain.pending());
        writer
            .write_all(b"discarded beyond limit discarded beyond limit")
            .unwrap();
        drain.turn();
        drop(writer);
        drain.turn();
        assert!(!drain.pending());
        let result = drain.publish();
        assert_eq!(result.status, OutputStatus::Cancelled);
        assert_eq!(result.bytes(), b"private-version");
        assert!(!format!("{result:?}").contains("private-version"));
        assert!(!format!("{:?}", OutputSnapshot::Finished(result)).contains("private-version"));
    }
    #[test]
    fn read_error_is_distinct_from_owner_cleanup_and_private() {
        let mut drain = Drain {
            reader: Some(std::fs::File::open(".").unwrap().into()),
            bytes: b"secret".to_vec(),
            limit: OutputLimit::new(32).unwrap(),
            status: None,
        };
        drain.turn();
        let result = drain.publish();
        assert_eq!(result.status, OutputStatus::ReadFailed);
        assert_eq!(result.bytes(), b"secret");
        assert!(!format!("{result:?}").contains("secret"));
    }
    #[test]
    fn owner_panic_without_published_output_is_terminal_after_join() {
        let state = Arc::new(std::sync::Mutex::new(super::super::Shared::default()));
        {
            let mut shared = super::super::lock(&state);
            shared.snapshot.started = true;
            shared.thread = Some(std::thread::spawn(|| panic!("fixture owner panic")));
        }
        let output = ProcessOutput(ProcessCleanup(state));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while matches!(output.snapshot(), OutputSnapshot::Running) {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        let OutputSnapshot::Finished(result) = output.snapshot() else {
            panic!("terminal output");
        };
        assert_eq!(result.status, OutputStatus::OwnerFailed);
        assert!(result.bytes().is_empty());
        let cleanup = output.0.snapshot();
        assert!(cleanup.thread_joined);
        assert_eq!(cleanup.error, Some("process_owner_panicked"));
    }
    #[test]
    fn first_capture_failure_survives_cancellation() {
        let (mut drain, mut writer) = local_pipe(1);
        writer.write_all(b"ab").unwrap();
        drain.turn();
        drain.cancel();
        assert_eq!(drain.publish().status, OutputStatus::LimitExceeded);
    }
}
