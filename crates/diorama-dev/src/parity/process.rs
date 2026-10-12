//! Sole-waiter process ownership. Numeric groups are never signalled after reap.
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn require(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits(),
        )?)
        .open(path)?;
    require(file.metadata()?.is_file(), "regular process log required")?;
    let mut data = Vec::new();
    file.take(limit.checked_add(1).ok_or("byte limit overflow")?)
        .read_to_end(&mut data)?;
    require(data.len() as u64 <= limit, "process log byte bound")?;
    Ok(data)
}
fn sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const HEX: &[u8; 16] = b"0123456789abcdef";
    Sha256::digest(data)
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect()
}
fn create_receipt(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(i32::try_from(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits(),
        )?)
        .open(path)?;
    require(file.metadata()?.is_file(), "regular receipt file required")?;
    Ok(file)
}
fn write_receipt(file: &mut File, value: &Value) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    serde_json::to_writer_pretty(&mut *file, value)?;
    file.write_all(b"\n")?;
    Ok(())
}
fn publish_marker(ready: &Path, pid: u32, before_publish: impl FnOnce(&Path)) -> Result<()> {
    let mut marker =
        tempfile::NamedTempFile::new_in(ready.parent().ok_or("marker parent missing")?)?;
    marker.write_all(pid.to_string().as_bytes())?;
    before_publish(marker.path());
    marker.persist_noclobber(ready)?;
    Ok(())
}
use rustix::process::{Pid, Signal};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn request(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
/// Own the signal reactor until every child and cleanup phase has settled.
/// Install only after handling the single-thread `__exec` route. Tokio's Unix
/// handlers remain installed for this process lifetime; tools install one guard
/// for their whole command and exit after dropping it.
#[derive(Debug)]
pub struct SignalGuard {
    runtime: Option<tokio::runtime::Runtime>,
    interrupt: tokio::task::JoinHandle<()>,
    terminate: tokio::task::JoinHandle<()>,
}
impl SignalGuard {
    /// Latch SIGINT and SIGTERM while synchronous command ownership work proceeds.
    /// # Errors
    /// Returns reactor/thread or signal-registration failures before any child spawn.
    pub fn install(cancellation: Cancellation) -> Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let (interrupt, terminate) = runtime.block_on(async {
            let mut interrupt = signal(SignalKind::interrupt())?;
            let mut terminate = signal(SignalKind::terminate())?;
            let other = cancellation.clone();
            Ok::<_, std::io::Error>((
                tokio::spawn(async move {
                    interrupt.recv().await;
                    cancellation.request();
                }),
                tokio::spawn(async move {
                    terminate.recv().await;
                    other.request();
                }),
            ))
        })?;
        Ok(Self {
            runtime: Some(runtime),
            interrupt,
            terminate,
        })
    }
}
impl Drop for SignalGuard {
    fn drop(&mut self) {
        self.interrupt.abort();
        self.terminate.abort();
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(1));
        }
    }
}

/// Keep this owner until settlement. Its child handle is the only waiter.
#[derive(Debug)]
pub struct OwnedChild {
    child: Child,
    status: Option<ExitStatus>,
    ready: PathBuf,
    group_authorized: bool,
    // Kept even on drop until the child is observed reaped. No automatic TempDir deletion.
    owner_directory: PathBuf,
}
#[derive(Debug)]
pub(crate) struct SpawnRequest<'a> {
    pub program: &'a Path,
    pub argv: &'a [OsString],
    pub environment: Option<&'a std::collections::BTreeMap<String, String>>,
    pub current_directory: Option<&'a Path>,
    pub input: File,
    pub stdout: Stdio,
    pub stderr: Stdio,
    pub byte_limit: u64,
    pub uid: Option<u32>,
    pub launcher: Option<&'a Path>,
}
impl OwnedChild {
    fn spawn_configured(
        mut command: Command,
        directory: tempfile::TempDir,
        ready: PathBuf,
    ) -> Result<Self> {
        let child = command.spawn()?;
        Ok(Self {
            child,
            status: None,
            ready,
            group_authorized: false,
            owner_directory: directory.keep(),
        })
    }
    pub(crate) fn spawn(request: SpawnRequest<'_>) -> Result<Self> {
        let SpawnRequest {
            program,
            argv,
            environment: env,
            current_directory: cwd,
            input,
            stdout,
            stderr,
            byte_limit: limit,
            uid,
            launcher,
        } = request;
        let directory = tempfile::Builder::new()
            .prefix("diorama-process-")
            .tempdir()?;
        let ready = directory.path().join("group-ready");
        let mut command = Command::new(
            launcher.map_or_else(std::env::current_exe, |path| Ok(path.to_path_buf()))?,
        );
        command
            .arg("__exec")
            .arg(&ready)
            .arg(limit.to_string())
            .arg(uid.map_or_else(|| "-".into(), |v| v.to_string()))
            .arg(program)
            .args(argv);
        if let Some(environment) = env {
            command.env_clear().envs(environment);
        }
        if let Some(path) = cwd {
            command.current_dir(path);
        }
        command.stdin(input).stdout(stdout).stderr(stderr);
        Self::spawn_configured(command, directory, ready)
    }
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }
    pub(crate) fn poll(&mut self) -> Result<Option<ExitStatus>> {
        if self.status.is_none() {
            self.status = self.child.try_wait()?;
        }
        if !self.group_authorized && self.ready.exists() {
            let data = read(&self.ready, 32)?;
            require(
                data == self.pid().to_string().as_bytes(),
                "owned child group handshake mismatch",
            )?;
            self.group_authorized = true;
        }
        Ok(self.status)
    }
    pub(crate) fn wait(&mut self, timeout: Duration) -> Result<ExitStatus> {
        let until = Instant::now() + timeout;
        loop {
            if let Some(status) = self.poll()? {
                return Ok(status);
            }
            require(Instant::now() < until, "owned child wait deadline")?;
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    pub(crate) fn signal(&mut self, signal: Signal) -> Result<()> {
        if self.poll()?.is_some() {
            return Ok(());
        }
        if self.group_authorized {
            match rustix::process::kill_process_group(
                Pid::from_raw(i32::try_from(self.pid())?).ok_or("invalid owned PID")?,
                signal,
            ) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
                Err(error) => Err(error.into()),
            }
        } else {
            // Before the child acknowledges setsid, target only the owned unreaped child.
            self.child.kill()?;
            Ok(())
        }
    }
    pub(crate) fn group_absent(&mut self) -> Result<bool> {
        require(
            self.poll()?.is_some(),
            "cannot certify group absence before reap",
        )?;
        if !self.group_authorized {
            return Ok(true);
        }
        match rustix::process::test_kill_process_group(
            Pid::from_raw(i32::try_from(self.pid())?).ok_or("invalid owned PID")?,
        ) {
            Err(rustix::io::Errno::SRCH) => Ok(true),
            Ok(()) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    /// Settle a raw child owner and remove its private handshake directory only
    /// after group absence. The caller must already have settled any output
    /// readers. A `CommandFailure` should normally be retained and observed,
    /// rather than using this method to promote its failed capture.
    pub fn settle(&mut self, errors: &mut Vec<String>) {
        self.settle_process(errors);
        if matches!(self.group_absent(), Ok(true)) {
            self.remove_metadata(errors);
        }
    }
    fn final_code(&mut self, errors: &mut Vec<String>) -> i32 {
        match self.poll() {
            Ok(status) => status.map_or(-1, exit_code),
            Err(error) => {
                errors.push(format!("final poll: {error}"));
                -1
            },
        }
    }
    fn remove_metadata(&self, errors: &mut Vec<String>) {
        if let Err(error) = fs::remove_dir_all(&self.owner_directory)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            errors.push(format!("process metadata removal: {error}"));
        }
    }
    /// Observe retained ownership without signaling or removing recovery files.
    /// # Errors
    /// Returns the underlying sole-waiter or process-group observation error.
    pub fn observe(&mut self) -> Result<Value> {
        let code = self.poll()?.map(exit_code);
        Ok(
            json!({"owned_pid":self.pid(),"exit_code":code,"owned_process_group_absent":if code.is_some(){Some(self.group_absent()?)}else{None},"owner_directory":self.owner_directory}),
        )
    }
    fn settle_process(&mut self, errors: &mut Vec<String>) {
        match self.poll() {
            Ok(Some(_)) => {},
            Ok(None) => {
                if let Err(e) = self.signal(Signal::TERM) {
                    errors.push(format!("terminate: {e}"));
                }
                if let Err(e) = self.wait(Duration::from_secs(5)) {
                    errors.push(format!("terminate wait: {e}"));
                    if let Err(e) = self.signal(Signal::KILL) {
                        errors.push(format!("kill: {e}"));
                    }
                    if let Err(e) = self.wait(Duration::from_secs(5)) {
                        errors.push(format!("kill wait: {e}"));
                    }
                }
            },
            Err(e) => errors.push(format!("owned child poll: {e}")),
        }
        match self.group_absent() {
            Ok(true) => {},
            Ok(false) => errors.push(
                "group absence unconfirmed; no post-reap signal sent; ownership files retained"
                    .into(),
            ),
            Err(e) => errors.push(format!("group absence: {e}; ownership files retained")),
        }
    }
}

pub fn child_exec(args: &[OsString]) -> Result<u8> {
    require(
        args.len() >= 5,
        "internal child requires ready-path/limit/uid/program",
    )?;
    let ready = Path::new(&args[1]);
    let limit: u64 = args[2].to_str().ok_or("limit UTF-8")?.parse()?;
    rustix::process::setsid()?;
    if limit != u64::MAX {
        rustix::process::setrlimit(
            rustix::process::Resource::Fsize,
            rustix::process::Rlimit {
                current: Some(limit),
                maximum: Some(limit),
            },
        )?;
    }
    publish_marker(ready, std::process::id(), |_| {})?;
    if args[3] != "-" {
        let id: u32 = args[3].to_str().ok_or("uid UTF-8")?.parse()?;
        #[cfg(target_os = "linux")]
        {
            rustix::thread::set_thread_groups(&[])?;
            rustix::thread::set_thread_gid(rustix::process::Gid::from_raw(id))?;
            rustix::thread::set_thread_uid(rustix::process::Uid::from_raw(id))?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = id;
            return Err("artifact UID isolation requires Linux".into());
        }
    }
    let error = Command::new(&args[4]).args(&args[5..]).exec();
    Err(error.into())
}
pub(crate) fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(1))
}

#[derive(Debug)]
pub struct CommandResult {
    pub code: i32,
    /// Lossy display text only. Parsers must use the exact byte fields below.
    /// In merged mode this contains the single combined stream.
    pub stdout: String,
    /// Empty in merged mode.
    pub stderr: String,
    pub stdout_bytes: Vec<u8>,
    pub stderr_bytes: Vec<u8>,
    pub receipt: Value,
}
/// Failure preserves settlement facts even when command logs cannot be read.
#[derive(Debug)]
pub struct CommandFailure {
    pub message: String,
    /// False means callers must retain their temporary input/context directories.
    pub cleanup_complete: bool,
    pub receipt: Value,
    /// Sole child owner retained when absence could not be confirmed. Do not
    /// reacquire numeric identities or signal a group after this owner reaped it.
    pub owner: Option<Box<OwnedChild>>,
}
impl std::fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (cleanup_complete={})",
            self.message, self.cleanup_complete
        )
    }
}
impl std::error::Error for CommandFailure {}
#[derive(Debug, Clone, Copy)]
pub enum OutputMode {
    Separate,
    Merged,
}
#[derive(Debug)]
struct StreamLog {
    stream: UnixStream,
    file: File,
    stored: u64,
    eof: bool,
}
#[derive(Debug)]
struct Logs {
    streams: Vec<StreamLog>,
    limit: u64,
    overflow: bool,
}
impl Logs {
    fn monitor(
        &mut self,
        child: &mut OwnedChild,
        cancellation: &Cancellation,
        timeout: Duration,
        timed_out: &mut bool,
        cancelled: &mut bool,
    ) -> Result<()> {
        let began = Instant::now();
        loop {
            *cancelled |= cancellation.requested();
            self.drain()?;
            if child.poll()?.is_some() {
                return Ok(());
            }
            *timed_out = began.elapsed() >= timeout;
            if *cancelled || *timed_out || self.overflow {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn new(output: &Path, error: &Path, merged: bool, limit: u64) -> Result<(Self, Stdio, Stdio)> {
        let make = |path: &Path| -> Result<(StreamLog, UnixStream)> {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())?)
                .open(path)?;
            let (reader, writer) = UnixStream::pair()?;
            reader.set_nonblocking(true)?;
            Ok((
                StreamLog {
                    stream: reader,
                    file,
                    stored: 0,
                    eof: false,
                },
                writer,
            ))
        };
        let (first, stdout) = make(output)?;
        let (streams, stderr) = if merged {
            (vec![first], stdout.try_clone()?)
        } else {
            let (second, stderr) = make(error)?;
            (vec![first, second], stderr)
        };
        Ok((
            Self {
                streams,
                limit,
                overflow: false,
            },
            Stdio::from(OwnedFd::from(stdout)),
            Stdio::from(OwnedFd::from(stderr)),
        ))
    }
    fn drain(&mut self) -> Result<()> {
        let mut buffer = [0; 4096];
        for log in &mut self.streams {
            // A producer cannot starve deadline/cancellation polling by flooding.
            for _ in 0..16 {
                let n = match log.stream.read(&mut buffer) {
                    Ok(0) => {
                        log.eof = true;
                        break;
                    },
                    Ok(n) => n,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                };
                let room = usize::try_from((self.limit - log.stored).min(n as u64))?;
                log.file.write_all(&buffer[..room])?;
                log.stored += room as u64;
                self.overflow |= n > room;
            }
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.drain()?;
            if self.streams.iter().all(|s| s.eof) {
                break;
            }
            require(Instant::now() < deadline, "command output EOF not observed")?;
            std::thread::sleep(Duration::from_millis(10));
        }
        for log in &mut self.streams {
            log.file.flush()?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy)]
pub struct CommandRequest<'a> {
    pub label: &'a str,
    pub argv: &'a [OsString],
    pub timeout: Duration,
    pub input: &'a [u8],
    pub required: bool,
    pub byte_limit: u64,
    pub mode: OutputMode,
    /// None inherits the environment; Some replaces it completely.
    pub environment: Option<&'a std::collections::BTreeMap<String, String>>,
    pub current_directory: Option<&'a Path>,
    /// Explicit executable implementing __exec; None uses this executable.
    pub launcher: Option<&'a Path>,
}
#[derive(Debug)]
pub struct Commands {
    pub output: PathBuf,
    pub cancellation: Cancellation,
}
fn check_command(
    label: &str,
    code: i32,
    required: bool,
    interrupted: bool,
    errors: &[String],
) -> Result<()> {
    require(
        errors.is_empty(),
        format!("{label}: cleanup/command failure: {errors:?}"),
    )?;
    require(
        !interrupted,
        format!("{label}: timeout, cancellation or output bound"),
    )?;
    require(
        !required || code == 0,
        format!("{label} failed with exit {code}"),
    )
}
#[derive(Debug)]
struct Prepared {
    owner: OwnedChild,
    logs: Logs,
    out: PathBuf,
    err: PathBuf,
    receipt_file: File,
}
impl Commands {
    fn prepare(&self, request: CommandRequest<'_>) -> Result<Prepared> {
        let CommandRequest {
            label,
            argv,
            input,
            byte_limit: limit,
            mode,
            environment,
            current_directory,
            launcher,
            ..
        } = request;
        require(!argv.is_empty(), "empty command")?;
        require(
            !self.cancellation.requested(),
            "operation cancelled before command spawn",
        )?;
        require(
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
            "invalid command label",
        )?;
        require(
            limit > 0 && limit <= 1024 * 1024 * 1024,
            "command byte limit must be 1..1GiB",
        )?;
        require(input.len() <= 8 * 1024 * 1024, "command input exceeds 8MiB")?;
        let merged = matches!(mode, OutputMode::Merged);
        let out = self
            .output
            .join(format!("{label}.{}", if merged { "log" } else { "stdout" }));
        let err = self.output.join(format!("{label}.stderr"));
        let mut input_file = tempfile::tempfile()?;
        input_file.write_all(input)?;
        input_file.seek(SeekFrom::Start(0))?;
        let (logs, stdout, stderr) = Logs::new(&out, &err, merged, limit)?;
        let mut receipt_file = create_receipt(&self.output.join(format!("{label}.command.json")))?;
        write_receipt(
            &mut receipt_file,
            &json!({"spawned":false,"cleanup_complete":true}),
        )?;
        let owner = OwnedChild::spawn(SpawnRequest {
            program: Path::new(&argv[0]),
            argv: &argv[1..],
            environment,
            current_directory,
            input: input_file,
            stdout,
            stderr,
            byte_limit: u64::MAX,
            uid: None,
            launcher,
        })?;
        Ok(Prepared {
            owner,
            logs,
            out,
            err,
            receipt_file,
        })
    }
    /// Convenience capture with separate stdout/stderr and inherited environment.
    /// # Errors
    /// The boxed error preserves `CommandFailure` for ownership-aware downcasting.
    pub fn run(
        &self,
        label: &str,
        argv: &[OsString],
        timeout: Duration,
        input: &[u8],
        required: bool,
        limit: u64,
    ) -> Result<CommandResult> {
        Ok(self.capture(CommandRequest {
            label,
            argv,
            timeout,
            input,
            required,
            byte_limit: limit,
            mode: OutputMode::Separate,
            environment: None,
            current_directory: None,
            launcher: None,
        })?)
    }
    /// Run a bounded owned command, retaining ownership through settlement.
    ///
    /// Each consuming executable must dispatch `child_exec` for `__exec` before
    /// creating threads. Empty input is a real EOF, not an inherited terminal.
    ///
    /// # Errors
    /// Failed setup, exit, deadline, output bound, cancellation or cleanup returns
    /// a typed failure. `cleanup_complete=false` requires retaining caller inputs.
    #[expect(
        clippy::too_many_lines,
        reason = "One error boundary retains the sole child owner and accumulated cleanup receipt"
    )]
    pub fn capture(
        &self,
        request: CommandRequest<'_>,
    ) -> std::result::Result<CommandResult, CommandFailure> {
        let mut cleanup_complete = true;
        let mut receipt = json!({"spawned":false,"owned_process_group_absent":true});
        let mut retained_owner = None;
        let outcome = (|| -> Result<CommandResult> {
            let CommandRequest {
                label,
                argv,
                timeout,
                required,
                byte_limit: limit,
                mode,
                ..
            } = request;
            let merged = matches!(mode, OutputMode::Merged);
            let Prepared {
                owner,
                mut logs,
                out,
                err,
                mut receipt_file,
            } = self.prepare(request)?;
            retained_owner = Some(owner);
            let child = retained_owner.as_mut().ok_or("spawned owner invariant")?;
            cleanup_complete = false;
            receipt = json!({"spawned":true,"owned_pid":child.pid(),"owner_directory":child.owner_directory,"owned_process_group_absent":false});
            let mut errors = Vec::new();
            let mut timed_out = false;
            let mut cancelled = false;
            let execution = logs.monitor(
                child,
                &self.cancellation,
                timeout,
                &mut timed_out,
                &mut cancelled,
            );
            if let Err(error) = execution {
                errors.push(error.to_string());
            }
            child.settle_process(&mut errors);
            match child.group_absent() {
                Ok(absent) => cleanup_complete = absent,
                Err(error) => errors.push(format!("final group observation: {error}")),
            }
            let group_absent = cleanup_complete;
            if let Err(error) = logs.finish() {
                cleanup_complete = false;
                errors.push(format!("output drain: {error}"));
            }
            if cleanup_complete {
                child.remove_metadata(&mut errors);
            }
            cancelled |= self.cancellation.requested();
            let code = child.final_code(&mut errors);
            receipt["owned_process_group_absent"] = json!(group_absent);
            receipt["cleanup_complete"] = json!(cleanup_complete);
            receipt["output_eof"] = json!(logs.streams.iter().all(|s| s.eof));
            receipt["cleanup_errors"] = json!(errors);
            receipt["exit_code"] = json!(code);
            receipt["timeout"] = json!(timed_out);
            receipt["cancelled"] = json!(cancelled);
            receipt["argv"] = json!(argv.iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>());
            receipt["merged_output"] = json!(merged);
            // Persist ownership facts before fallible log reads, then augment hashes.
            write_receipt(&mut receipt_file, &receipt)?;
            let stdout = read(&out, limit)?;
            let stderr = if merged {
                Vec::new()
            } else {
                read(&err, limit)?
            };
            receipt["output_limit"] = json!(logs.overflow);
            receipt["stdout_sha256"] = json!(sha256(&stdout));
            receipt["stderr_sha256"] = json!(sha256(&stderr));
            cancelled |= self.cancellation.requested();
            receipt["cancelled"] = json!(cancelled);
            write_receipt(&mut receipt_file, &receipt)?;
            check_command(
                label,
                code,
                required,
                timed_out || cancelled || logs.overflow,
                &errors,
            )?;
            Ok(CommandResult {
                code,
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
                stdout_bytes: stdout,
                stderr_bytes: stderr,
                receipt: receipt.clone(),
            })
        })();
        outcome.map_err(|error| CommandFailure {
            message: error.to_string(),
            cleanup_complete,
            receipt,
            owner: if cleanup_complete {
                None
            } else {
                retained_owner.map(Box::new)
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handshake_is_invisible_until_complete_publication() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let ready = directory.path().join("ready");
        publish_marker(&ready, 12345, |temporary| {
            assert!(!ready.exists());
            assert_eq!(fs::read(temporary).unwrap(), b"12345");
            std::thread::sleep(Duration::from_millis(10));
            assert!(!ready.exists());
        })?;
        assert_eq!(read(&ready, 32)?, b"12345");
        assert!(publish_marker(&ready, 67890, |_| {}).is_err());
        assert_eq!(read(&ready, 32)?, b"12345");
        Ok(())
    }
    #[test]
    fn receipt_rejects_symlink_and_updates_only_owned_descriptor() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let target = directory.path().join("target");
        fs::write(&target, b"preserved")?;
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link)?;
        assert!(create_receipt(&link).is_err());
        let receipt = directory.path().join("receipt");
        let mut descriptor = create_receipt(&receipt)?;
        write_receipt(&mut descriptor, &json!({"owned":true}))?;
        fs::remove_file(&receipt)?;
        std::os::unix::fs::symlink(&target, &receipt)?;
        write_receipt(&mut descriptor, &json!({"settled":true}))?;
        assert_eq!(fs::read(target)?, b"preserved");
        Ok(())
    }
}
