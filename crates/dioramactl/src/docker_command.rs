//! Bounded synchronous Docker calls with one thread owning the CLI child and capture files.
use std::{
    fmt, io,
    io::Read,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

pub(crate) struct CommandOutput {
    pub successful: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl fmt::Debug for CommandOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandOutput")
            .field("successful", &self.successful)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .finish()
    }
}

const RETAINED_BYTES: u64 = 8 * 1024 * 1024;
const POLL: Duration = Duration::from_millis(10);
const CLEANUP: Duration = Duration::from_secs(1);

pub(crate) fn output(program: &str, args: &[&str], timeout: Duration) -> io::Result<CommandOutput> {
    let began = Instant::now();
    let deadline = began
        .checked_add(timeout)
        .ok_or_else(|| io::Error::other("invalid Docker deadline"))?;
    let caller_budget = timeout
        .checked_add(CLEANUP)
        .ok_or_else(|| io::Error::other("invalid Docker deadline"))?;
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null());
    let cancelled = Arc::new(AtomicBool::new(false));
    let owner_cancelled = cancelled.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    // Construct the owner before it spawns the child. The caller never joins:
    // delayed kernel spawn/reap or file I/O cannot turn its deadline into an
    // unbounded wait. The owner retains the child and private files until reap.
    std::thread::Builder::new()
        .name("diorama-docker-owner".into())
        .spawn(move || {
            let result = run(command, deadline, &owner_cancelled);
            let _ = sender.send(result);
        })?;
    match receiver.recv_timeout(caller_budget.saturating_sub(began.elapsed())) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            cancelled.store(true, Ordering::Release);
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Docker command exceeded its deadline; child cleanup is not confirmed",
            ))
        },
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("Docker command owner failed"))
        },
    }
}

/// Drop runs exclusively on the owner thread. It retains the unreaped Child
/// identity across kill and wait, including on an I/O error or unwinding.
struct OwnedChild(Option<Child>);
impl OwnedChild {
    fn poll(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.0.as_mut().expect("owned child").try_wait()?;
        if status.is_some() {
            // try_wait reaped this identity: never signal it again.
            self.0.take();
        }
        Ok(status)
    }
    fn kill(&mut self) -> io::Result<()> {
        self.0.as_mut().expect("owned child").kill()
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run(
    mut command: Command,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<CommandOutput> {
    let stdout = tempfile::NamedTempFile::new()?;
    let stderr = tempfile::NamedTempFile::new()?;
    command
        .stdout(Stdio::from(stdout.as_file().try_clone()?))
        .stderr(Stdio::from(stderr.as_file().try_clone()?));
    if Instant::now() >= deadline || cancelled.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Docker command exceeded its deadline before spawn",
        ));
    }
    // Declared after the files, so its Drop completes before capture removal.
    let mut child = OwnedChild(Some(command.spawn()?));
    let mut failure = None;
    let mut cleanup_deadline = None;
    loop {
        if let Some(status) = child.poll()? {
            if let Some(error) = failure {
                return Err(error);
            }
            if Instant::now() >= deadline || cancelled.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Docker command exceeded its deadline",
                ));
            }
            return Ok(CommandOutput {
                successful: status.success(),
                stdout: read_output(stdout.path())?,
                stderr: read_output(stderr.path())?,
            });
        }
        if failure.is_none() {
            if Instant::now() >= deadline || cancelled.load(Ordering::Acquire) {
                failure = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Docker command exceeded its deadline",
                ));
            } else if stdout.as_file().metadata()?.len() > RETAINED_BYTES
                || stderr.as_file().metadata()?.len() > RETAINED_BYTES
            {
                failure = Some(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Docker command output exceeds the retention limit",
                ));
            }
            if failure.is_some() {
                // kill errors remain errors; Drop still retains/reaps the child.
                child.kill()?;
                cleanup_deadline = Instant::now().checked_add(CLEANUP);
            }
        }
        if cleanup_deadline.is_some_and(|until| Instant::now() >= until) {
            // Drop may block in kernel wait only on this detached owner thread.
            // The caller's recv_timeout returns an explicit unconfirmed error.
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Docker child cleanup is not confirmed",
            ));
        }
        std::thread::sleep(POLL);
    }
}

fn read_output(path: &std::path::Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(RETAINED_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > RETAINED_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Docker command output exceeds the retention limit",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn command_preserves_separate_streams_and_exit_status_inside_runtime() {
        for code in [0, 7] {
            let script = format!("printf stdout; printf stderr >&2; exit {code}");
            let output = output("/bin/sh", &["-c", &script], Duration::from_secs(5)).unwrap();
            assert_eq!(output.successful, code == 0);
            assert_eq!(output.stdout, b"stdout");
            assert_eq!(output.stderr, b"stderr");
        }
    }

    #[cfg(unix)]
    #[test]
    fn deadline_kills_and_reaps_the_owned_cli_child() {
        let began = Instant::now();
        // exec replaces the shell with the direct owned child; no group claim.
        let error = output(
            "/bin/sh",
            &["-c", "exec sleep 60"],
            Duration::from_millis(500),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!error.to_string().contains("not confirmed"), "{error}");
        assert!(began.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn a_short_lived_command_cannot_succeed_after_the_execution_deadline() {
        // Completion may be observed after the process has exited between
        // polls. The cleanup allowance must never extend execution success.
        let error = output(
            "/bin/sh",
            &["-c", "exec sleep 0.02"],
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[cfg(unix)]
    #[test]
    fn output_limit_stops_a_noisy_command_before_its_deadline() {
        let began = Instant::now();
        let error = output(
            "/bin/sh",
            &["-c", "dd if=/dev/zero bs=1048576 count=10; exec sleep 60"],
            Duration::from_secs(10),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(began.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn retained_output_read_rejects_oversize_without_reading_the_whole_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(RETAINED_BYTES + 1).unwrap();
        assert_eq!(
            read_output(file.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
