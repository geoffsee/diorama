//! Static observer running only in an explicitly opted-in disposable Linux guest.
#[path = "constrained_diagnostics.rs"]
mod diagnostics;
use crate::process::{Cancellation, CommandFailure, OwnedChild, SignalGuard, SpawnRequest};
use diorama_dev::{Result, sha256};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::OwnedFd,
        unix::{
            fs::MetadataExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
const BUNDLE: &str = "/tmp/diorama-bundle";
const EXTERNAL: &str = "/tmp/external-runtime";
const CONTROLS: [&str; 3] = [
    "/proc/sys/net/ipv6/conf/all/disable_ipv6",
    "/proc/sys/net/ipv6/conf/default/disable_ipv6",
    "/proc/sys/net/ipv6/conf/lo/disable_ipv6",
];
fn require(value: bool, message: &str) -> Result<()> {
    if value { Ok(()) } else { Err(message.into()) }
}
fn read(path: impl AsRef<Path>, limit: u64) -> Result<Vec<u8>> {
    let fd = rustix::fs::open(
        path.as_ref(),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    bounded_file(File::from(fd), limit)
}
fn bounded_file(file: File, limit: u64) -> Result<Vec<u8>> {
    require(file.metadata()?.is_file(), "regular observation input")?;
    let mut raw = Vec::new();
    file.take(limit + 1).read_to_end(&mut raw)?;
    require(raw.len() as u64 <= limit, "observation budget")?;
    Ok(raw)
}
fn text(path: impl AsRef<Path>, limit: u64) -> Result<String> {
    Ok(String::from_utf8(read(path, limit)?)?)
}
fn digest(path: impl AsRef<Path>) -> Result<String> {
    Ok(sha256(&read(path, 32 * 1024 * 1024)?))
}
fn emit(value: &Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, value)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
fn identity(pid: u32) -> Result<Value> {
    let raw = text(format!("/proc/{pid}/stat"), 8192)?;
    let (_, tail) = raw.rsplit_once(") ").ok_or("process stat")?;
    let fields = tail.split_whitespace().collect::<Vec<_>>();
    require(
        fields.len() > 19 && !matches!(fields[0], "Z" | "X"),
        "live process",
    )?;
    // /proc/PID/exe is a kernel-owned link; retain the opened descriptor while hashing.
    let exe = bounded_file(File::open(format!("/proc/{pid}/exe"))?, 32 * 1024 * 1024)?;
    Ok(
        json!({"pid":pid,"starttime":fields[19].parse::<u64>()?,"exe_sha256":sha256(&exe),"mnt":fs::read_link(format!("/proc/{pid}/ns/mnt"))?.to_str().ok_or("namespace UTF8")?,"cgroup":text(format!("/proc/{pid}/cgroup"),8192)?}),
    )
}
fn file_identity(path: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(path)?;
    Ok(json!({"device":m.dev(),"inode":m.ino(),"mode":m.mode(),"uid":m.uid(),"gid":m.gid()}))
}
fn external(pid: u32) -> Result<Value> {
    let mut value = identity(pid)?;
    let socket = file_identity(&Path::new(EXTERNAL).join("containerd.sock"))?;
    require(
        socket["mode"].as_u64().ok_or("socket mode")? & 0o170_000 == 0o140_000,
        "external socket remains socket",
    )?;
    value["socket"] = socket;
    value["configuration"] = json!({"identity":file_identity(&Path::new(EXTERNAL).join("config.toml"))?,"sha256":digest(Path::new(EXTERNAL).join("config.toml"))?});
    Ok(value)
}
fn sentinels() -> Result<Value> {
    let mut values = serde_json::Map::new();
    for root in ["/etc/init.d", "/etc/cni/net.d", EXTERNAL] {
        let path = Path::new(root);
        if !path.exists() {
            values.insert(root.into(), Value::Null);
            continue;
        }
        let mut entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        require(entries.len() <= 256, "sentinel inventory bound")?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let mut rows = serde_json::Map::new();
        for entry in entries {
            let mut data = file_identity(&entry.path())?;
            let ty = entry.file_type()?;
            if ty.is_symlink() {
                data["link"] = json!(fs::read_link(entry.path())?.to_str().ok_or("link UTF8")?);
            } else if ty.is_file() {
                data["sha256"] = json!(digest(entry.path())?);
            }
            rows.insert(
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "sentinel UTF8")?,
                data,
            );
        }
        values.insert(root.into(), rows.into());
    }
    Ok(values.into())
}
fn scalars(prefix: &str) -> Result<Value> {
    let mut values = Vec::new();
    for path in CONTROLS {
        let raw = text(format!("{prefix}{path}"), 64)?;
        require(
            matches!(raw.as_str(), "0" | "0\n" | "1" | "1\n"),
            "kernel scalar grammar",
        )?;
        values.push(raw.trim().parse::<u64>()?);
    }
    Ok(json!(values))
}
fn outside(pid: u32) -> Result<Value> {
    Ok(
        json!({"external":external(pid)?,"sentinels":sentinels()?,"observer_mnt":fs::read_link("/proc/self/ns/mnt")?.to_str().ok_or("namespace UTF8")?,"root_enabled":text("/sys/fs/cgroup/cgroup.subtree_control",4096)?,"observer_mounts":text("/proc/self/mountinfo",256*1024)?,"outside_values":scalars("")?}),
    )
}
fn record(mut value: Value, event: &str, case: &str) -> Value {
    value["schema"] = json!(1);
    value["event"] = json!(event);
    value["case"] = json!(case);
    value
}
struct Child {
    owner: Option<OwnedChild>,
    gate: Option<UnixStream>,
    out: PathBuf,
    err: PathBuf,
}
impl Child {
    fn spawn(label: &str, program: &Path, args: &[&str]) -> Result<Self> {
        let out = PathBuf::from(format!("/tmp/constrained-{label}.out"));
        let err = PathBuf::from(format!("/tmp/constrained-{label}.err"));
        let stdout = OpenOptions::new().write(true).create_new(true).open(&out)?;
        let stderr = OpenOptions::new().write(true).create_new(true).open(&err)?;
        let (gate, input) = UnixStream::pair()?;
        gate.set_write_timeout(Some(Duration::from_secs(1)))?;
        let arguments = args
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>();
        let owner = OwnedChild::spawn(SpawnRequest {
            program,
            argv: &arguments,
            environment: None,
            current_directory: None,
            input: File::from(OwnedFd::from(input)),
            stdout: Stdio::from(stdout),
            stderr: Stdio::from(stderr),
            byte_limit: 1024 * 1024,
            uid: None,
            launcher: None,
        })?;
        Ok(Self {
            owner: Some(owner),
            gate: Some(gate),
            out,
            err,
        })
    }
    fn owner(&mut self) -> Result<&mut OwnedChild> {
        self.owner
            .as_mut()
            .ok_or_else(|| "child owner consumed".into())
    }
    fn pid(&self) -> Result<u32> {
        Ok(self.owner.as_ref().ok_or("child owner consumed")?.pid())
    }
    fn send(&mut self, byte: u8) -> Result<()> {
        self.gate
            .as_mut()
            .ok_or("closed input")?
            .write_all(&[byte])?;
        Ok(())
    }
    fn cancel_candidate(&mut self) -> Result<()> {
        let owner = self.owner()?;
        require(owner.poll()?.is_none(), "candidate live at cancellation")?;
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(i32::try_from(owner.pid())?).ok_or("owned PID")?,
            rustix::process::Signal::TERM,
        )?;
        Ok(())
    }
    fn settle(&mut self) -> Result<()> {
        self.gate.take();
        let owner = self.owner()?;
        let mut errors = Vec::new();
        owner.settle(&mut errors);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; ").into())
        }
    }
    fn failure(&mut self, message: String) -> diorama_dev::Error {
        let receipt = self
            .owner
            .as_mut()
            .and_then(|o| o.observe().ok())
            .unwrap_or_else(|| json!({"cleanup_complete":false}));
        let clean = receipt["owned_process_group_absent"] == true;
        Box::new(CommandFailure {
            message,
            cleanup_complete: clean,
            receipt,
            owner: if clean {
                None
            } else {
                self.owner.take().map(Box::new)
            },
        })
    }
    fn finish(&mut self, seconds: u64) -> Result<i32> {
        self.gate.take();
        let status = self.owner()?.wait(Duration::from_secs(seconds))?;
        let code = crate::process::exit_code(status);
        self.settle()?;
        Ok(code)
    }
}
struct Observer {
    keeper: Child,
    deadline: Instant,
    cancel: Cancellation,
}
impl Observer {
    fn check(&self, until: Instant) -> Result<()> {
        require(!self.cancel.requested(), "observer cancelled")?;
        require(
            Instant::now() < until.min(self.deadline),
            "observer deadline",
        )
    }
    fn wait_event(&mut self, child: &mut Child, event: &str) -> Result<()> {
        let until = Instant::now() + Duration::from_mins(3);
        loop {
            self.check(until)?;
            if events(&child.out, false)?
                .iter()
                .any(|r| r["event"] == event)
            {
                return Ok(());
            }
            require(
                child.owner()?.poll()?.is_none(),
                "candidate exited before event",
            )?;
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn wait_file(&mut self, child: &mut Child, path: &Path) -> Result<()> {
        let until = Instant::now() + Duration::from_secs(10);
        while !path.exists() {
            self.check(until)?;
            require(
                child.owner()?.poll()?.is_none(),
                "candidate exited before double",
            )?;
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
    fn observe(&mut self, child: &Child, phase: &str, case: &str) -> Result<()> {
        let pid = child.pid()?;
        let mut value = outside(self.keeper.pid()?)?;
        value["identity"] = identity(pid)?;
        value["mounts"] = json!(text(format!("/proc/{pid}/mountinfo"), 256 * 1024)?);
        value["visible_values"] = scalars(&format!("/proc/{pid}/root"))?;
        value["phase"] = json!(phase);
        emit(&record(value, "observation", case))
    }
    fn finish_candidate(&self, child: &mut Child) -> Result<i32> {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            self.check(until)?;
            if child.owner()?.poll()?.is_some() {
                return child.finish(0);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn run_case(&mut self, case: &str, value: u64) -> Result<()> {
        self.check(self.deadline)?;
        for path in CONTROLS {
            fs::write(path, value.to_string())?;
        }
        require(
            scalars("")? == json!([value, value, value]),
            "explicit initial sysctls",
        )?;
        let before = outside(self.keeper.pid()?)?;
        emit(&record(before.clone(), "before", case))?;
        let spawned = Child::spawn(
            case,
            Path::new("/usr/bin/unshare"),
            &[
                "--mount",
                "--propagation",
                "private",
                "/bin/sh",
                "/tmp/diorama-bundle/namespace.sh",
                case,
            ],
        );
        let mut child = match spawned {
            Ok(child) => child,
            Err(error) => {
                let diagnostic = diagnostics::failure_record(
                    case,
                    None,
                    &error.to_string(),
                    &PathBuf::from(format!("/tmp/constrained-{case}.out")),
                    &PathBuf::from(format!("/tmp/constrained-{case}.err")),
                    || Ok(()),
                );
                let _ = emit(&diagnostic);
                return Err(error);
            },
        };
        let result = self.case_protocol(&mut child, case, &before);
        if let Err(error) = result {
            let pid = child.pid().ok();
            let out = child.out.clone();
            let err = child.err.clone();
            let diagnostic =
                diagnostics::failure_record(case, pid, &error.to_string(), &out, &err, || {
                    child.settle()
                });
            let failure = child.failure(format!(
                "case {case}: {error}; cleanup={}",
                diagnostic["cleanup_error"]
            ));
            let _ = emit(&diagnostic);
            return Err(failure);
        }
        Ok(())
    }
    fn case_protocol(&mut self, child: &mut Child, case: &str, before: &Value) -> Result<()> {
        self.wait_event(child, "READY")?;
        self.observe(child, "READY", case)?;
        self.check(self.deadline)?;
        child.send(b'G')?;
        let mut double = None;
        if case == "cancel" {
            let marker = Path::new("/tmp/constrained-module-double.pid");
            self.wait_file(child, marker)?;
            let raw = text(marker, 256)?;
            let parts = raw.split_whitespace().collect::<Vec<_>>();
            require(parts.len() == 2, "double marker shape")?;
            let pid = parts[0].parse::<u32>()?;
            double = Some(pid);
            emit(
                &json!({"schema":1,"event":"double_started","case":case,"module":parts[1],"identity":identity(pid)?}),
            )?;
            child.cancel_candidate()?;
        } else if case != "guard" {
            self.wait_event(child, "FIRST")?;
            self.observe(child, "FIRST", case)?;
            self.check(self.deadline)?;
            child.send(b'R')?;
            self.wait_event(child, "SECOND")?;
            self.observe(child, "SECOND", case)?;
            self.check(self.deadline)?;
            child.send(b'Q')?;
        }
        let code = self.finish_candidate(child)?;
        let pid = child.pid()?;
        emit(
            &json!({"schema":1,"event":"consumer","case":case,"pid":pid,"exit":code,"events":events(&child.out,true)?,"stderr":text(&child.err,1024*1024)?}),
        )?;
        require(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "candidate reaped",
        )?;
        if case == "guard" {
            emit(
                &json!({"schema":1,"event":"guard_calls","value":text("/tmp/constrained-guard-double.calls",256)?}),
            )?;
        }
        if let Some(pid) = double {
            require(
                !Path::new(&format!("/proc/{pid}")).exists(),
                "owned module double absent",
            )?;
            emit(&json!({"schema":1,"event":"double_absent","pid":pid}))?;
        }
        let mut after = outside(self.keeper.pid()?)?;
        require(after == *before, "outside resources unchanged")?;
        after["pid_absent"] = json!(pid);
        emit(&record(after, "after", case))
    }
    fn setup(&mut self) -> Result<()> {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            self.check(until)?;
            if read(&self.keeper.out, 64)? == b"READY\n" {
                break;
            }
            require(
                self.keeper.owner()?.poll()?.is_none(),
                "keeper exited before readiness",
            )?;
            std::thread::sleep(Duration::from_millis(10));
        }
        let version = one_command(
            "unshare-version",
            Path::new("/usr/bin/unshare"),
            &["--version"],
            5,
            &self.cancel,
            self.deadline,
        )?;
        require(
            version.0 == 0 && version.2.is_empty(),
            "namespace version command",
        )?;
        emit(
            &json!({"schema":1,"event":"setup","launcher_argv":["/usr/bin/unshare","--mount","--propagation","private"],"unshare_version":version.1.trim(),"unshare_sha256":digest("/usr/bin/unshare")?,"candidate_sha256":digest(format!("{BUNDLE}/prepare_node_host"))?,"external":external(self.keeper.pid()?)?}),
        )?;
        let flags = [
            "--no-container-mode",
            "--disable-ipv6",
            "--container-runtime-endpoint=unix:///tmp/external-runtime/containerd.sock",
            "--print-config",
        ];
        let cli = one_command(
            "cli",
            Path::new("/tmp/diorama-bundle/prepare_node_host"),
            &flags,
            10,
            &self.cancel,
            self.deadline,
        )?;
        emit(
            &json!({"schema":1,"event":"cli","argv":flags,"exit":cli.0,"stdout":cli.1,"stderr":cli.2}),
        )?;
        require(cli.0 == 0, "guest flag grammar")
    }
}
fn events(path: &Path, complete: bool) -> Result<Vec<Value>> {
    let raw = read(path, 1024 * 1024)?;
    require(
        !complete || raw.ends_with(b"\n"),
        "complete consumer records",
    )?;
    raw.split_inclusive(|b| *b == b'\n')
        .filter(|line| line.ends_with(b"\n"))
        .map(diorama_dev::json::parse)
        .collect()
}
fn one_command(
    label: &str,
    program: &Path,
    args: &[&str],
    seconds: u64,
    cancellation: &Cancellation,
    deadline: Instant,
) -> Result<(i32, String, String)> {
    let mut child = Child::spawn(label, program, args)?;
    let result = (|| {
        let until = (Instant::now() + Duration::from_secs(seconds)).min(deadline);
        while child.owner()?.poll()?.is_none() {
            require(
                !cancellation.requested() && Instant::now() < until,
                "command cancelled/deadline",
            )?;
            std::thread::sleep(Duration::from_millis(10));
        }
        let code = child.finish(0)?;
        require(
            !cancellation.requested(),
            "command cancelled during settlement",
        )?;
        Ok((
            code,
            text(&child.out, 1024 * 1024)?,
            text(&child.err, 1024 * 1024)?,
        ))
    })();
    if let Err(error) = result {
        let cleanup = child.settle();
        return Err(child.failure(format!("command {label}: {error}; cleanup={cleanup:?}")));
    }
    result
}
fn keeper() -> Result<u8> {
    disposable_guard()?;
    let listener = UnixListener::bind(Path::new(EXTERNAL).join("containerd.sock"))?;
    println!("READY");
    std::io::stdout().flush()?;
    let mut byte = [0];
    require(
        std::io::stdin().read(&mut byte)? == 0,
        "keeper orderly input close",
    )?;
    drop(listener);
    Ok(0)
}
#[derive(Debug)]
struct CleanupFailure {
    original: diorama_dev::Error,
    cleanup: diorama_dev::Error,
}
impl std::fmt::Display for CleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; keeper cleanup: {}", self.original, self.cleanup)
    }
}
impl std::error::Error for CleanupFailure {}
fn disposable_guard() -> Result<()> {
    require(
        cfg!(target_os = "linux")
            && rustix::process::geteuid().is_root()
            && std::env::var("DIORAMA_RUN_PREPARATION").as_deref() == Ok("1"),
        "explicit disposable Linux guest opt-in",
    )
}
fn run(cancel: Cancellation) -> Result<()> {
    disposable_guard()?;
    fs::create_dir(EXTERNAL)?;
    fs::write(
        Path::new(EXTERNAL).join("config.toml"),
        "owned external-runtime sentinel\n",
    )?;
    let keeper = Child::spawn("keeper", &std::env::current_exe()?, &["--keeper"])?;
    let mut observer = Observer {
        keeper,
        deadline: Instant::now() + Duration::from_mins(8),
        cancel,
    };
    let result = (|| -> Result<()> {
        observer.setup()?;
        for (case, value) in [
            ("correct", 1),
            ("needs_write", 0),
            ("guard", 0),
            ("cancel", 0),
        ] {
            observer.run_case(case, value)?;
        }
        observer.check(observer.deadline)?;
        require(observer.keeper.finish(5)? == 0, "keeper orderly exit")?;
        observer.check(observer.deadline)?;
        let pid = observer.keeper.pid()?;
        require(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "keeper reaped",
        )?;
        fs::remove_file(Path::new(EXTERNAL).join("containerd.sock"))?;
        emit(&json!({"schema":1,"event":"complete","keeper_pid_absent":pid,"socket_removed":true}))
    })();
    let cleanup = observer.keeper.settle();
    match (result, cleanup) {
        (Ok(()), Ok(())) => observer.check(observer.deadline),
        (Err(error), Ok(())) => Err(error),
        (result, Err(cleanup)) => {
            let cleanup = observer.keeper.failure(cleanup.to_string());
            Err(Box::new(CleanupFailure {
                original: result
                    .err()
                    .unwrap_or_else(|| "keeper cleanup failed".into()),
                cleanup,
            }))
        },
    }
}
pub(super) fn main() -> Result<u8> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|s| s == "__exec") {
        return crate::process::child_exec(&args);
    }
    if args == [std::ffi::OsString::from("--keeper")] {
        return keeper();
    }
    require(args.is_empty(), "guest observer takes no arguments")?;
    let cancel = Cancellation::default();
    let _signals = SignalGuard::install(cancel.clone())?;
    match run(cancel) {
        Ok(()) => Ok(0),
        Err(error) => {
            let _ = emit(
                &json!({"schema":1,"event":"failure","kind":"RustError","message":error.to_string()}),
            );
            Err(error)
        },
    }
}
