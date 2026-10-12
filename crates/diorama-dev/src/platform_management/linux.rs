//! Disposable container-only management executable fixture.
use super::{Result, oracle, require};
use crate::process::{
    Cancellation, CommandFailure, CommandRequest, Commands, OutputMode, SignalGuard,
};
use serde_json::{Value, json};
use std::os::unix::process::CommandExt;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Debug)]
struct FailedRuntime {
    error: CommandFailure,
    root: Option<tempfile::TempDir>,
    logs: Option<tempfile::TempDir>,
    _signals: SignalGuard,
}
impl std::fmt::Display for FailedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for FailedRuntime {}
impl Drop for FailedRuntime {
    fn drop(&mut self) {
        if !self.error.cleanup_complete {
            if let Some(root) = self.root.take() {
                let _ = root.keep();
            }
            if let Some(logs) = self.logs.take() {
                let _ = logs.keep();
            }
        }
    }
}

const FILES: &[(&str, &str)] = &[
    ("proc/version", "Linux version fixture compiler\n"),
    ("proc/modules", "xt_comment 1 0 - Live 0x0\n"),
    ("proc/net/ip_tables_matches", "comment\n"),
    (
        "sys/fs/cgroup/cgroup.controllers",
        "cpuset cpu io memory pids\n",
    ),
    ("lib/modules/fixture/kernel/net/netfilter/xt_comment.ko", ""),
];
fn free_ports() -> Result<()> {
    let listeners = [2379, 6443, 10443, 6060]
        .map(|port| TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)));
    for listener in listeners {
        listener?;
    }
    Ok(())
}
#[expect(
    clippy::too_many_lines,
    reason = "Ordered private fixture lifecycle retains all owned resources"
)]
pub fn runtime() -> Result<()> {
    require(
        cfg!(target_os = "linux")
            && rustix::process::getuid().as_raw() == 0
            && std::env::var("DIORAMA_MANAGEMENT_DISPOSABLE").as_deref() == Ok("1"),
        "explicit disposable root Linux fixture required",
    )?;
    let root = tempfile::Builder::new()
        .prefix("diorama-check-")
        .tempdir()?;
    let logs = tempfile::Builder::new()
        .prefix("diorama-check-commands-")
        .tempdir()?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755))?;
    fs::copy("/dioramactl", root.path().join("dioramactl"))?;
    fs::set_permissions(
        root.path().join("dioramactl"),
        fs::Permissions::from_mode(0o755),
    )?;
    for (path, value) in FILES {
        let path = root.path().join(path);
        fs::create_dir_all(path.parent().ok_or("fixture path")?)?;
        fs::write(path, value)?;
    }
    let cancellation = Cancellation::default();
    let signals = SignalGuard::install(cancellation.clone())?;
    let commands = Commands {
        output: logs.path().to_owned(),
        cancellation,
    };
    let mut rows = Vec::new();
    let executable = std::env::current_exe()?;
    let cases: [(&str, &[&str], u32); 9] = [
        ("help", &["check", "--help"], 65534),
        ("version", &["version"], 65534),
        ("root_pass", &["check"], 0),
        ("nonroot", &["check"], 65534),
        ("preparation", &["check", "--install-prereqs"], 0),
        ("pprof_off", &["check"], 0),
        ("pprof_conflict", &["check", "--pprof-server"], 0),
        ("repeat_0", &["check", "--pprof-server"], 0),
        ("repeat_1", &["check", "--pprof-server"], 0),
    ];
    let mut listener = None;
    for (name, args, uid) in cases {
        if name == "pprof_off" {
            listener = Some(TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 6060))?);
        }
        if name == "repeat_0" {
            require(
                listener.as_ref().is_some_and(|l| l.local_addr().is_ok()),
                "listener preserved",
            )?;
            drop(listener.take());
            free_ports()?;
        }
        let mut argv = vec![
            executable.clone().into_os_string(),
            "__chroot".into(),
            root.path().as_os_str().to_owned(),
            uid.to_string().into(),
        ];
        argv.extend(args.iter().map(OsString::from));
        let environment = BTreeMap::from([("DIORAMA_MANAGEMENT_DISPOSABLE".into(), "1".into())]);
        let result = match commands.capture(CommandRequest {
            label: name,
            argv: &argv,
            timeout: Duration::from_secs(5),
            input: b"",
            required: false,
            byte_limit: 65536,
            mode: OutputMode::Separate,
            environment: Some(&environment),
            current_directory: None,
            launcher: None,
        }) {
            Ok(result) => result,
            Err(error) => {
                return Err(Box::new(FailedRuntime {
                    error,
                    root: Some(root),
                    logs: Some(logs),
                    _signals: signals,
                }));
            },
        };
        rows.push(json!({"name":name,"exit":result.code,"stdout":std::str::from_utf8(&result.stdout_bytes)?,"stderr":std::str::from_utf8(&result.stderr_bytes)?}));
        if name.starts_with("repeat_") {
            free_ports()?;
        }
    }
    for (path, expected) in FILES {
        require(
            fs::read(root.path().join(path))? == expected.as_bytes(),
            "fixture files unchanged",
        )?;
    }
    let record: Value =
        json!({"cases":rows,"listener_survived":true,"ports_released":true,"files_unchanged":true});
    oracle::management_record(&record)?;
    require(
        !commands.cancellation.requested(),
        "management runtime cancelled",
    )?;
    println!("DIORAMA_CHECK {}", serde_json::to_string(&record)?);
    Ok(())
}
/// This dispatch occurs before any signal runtime or thread is created.
pub fn chroot_exec(args: &[OsString]) -> Result<()> {
    require(
        cfg!(target_os = "linux")
            && rustix::process::getuid().as_raw() == 0
            && std::env::var("DIORAMA_MANAGEMENT_DISPOSABLE").as_deref() == Ok("1"),
        "disposable chroot marker required",
    )?;
    require(args.len() >= 3, "chroot arguments")?;
    let root = PathBuf::from(&args[0]);
    require(
        root.parent() == Some(Path::new("/tmp"))
            && root
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("diorama-check-")),
        "owned chroot root",
    )?;
    let uid = args[1].to_str().ok_or("uid encoding")?.parse::<u32>()?;
    require(matches!(uid, 0 | 65534), "fixture uid")?;
    rustix::process::chroot(&root)?;
    std::env::set_current_dir("/")?;
    #[cfg(target_os = "linux")]
    if uid != 0 {
        rustix::thread::set_thread_uid(rustix::process::Uid::from_raw(uid))?;
    }

    Err(std::process::Command::new("/dioramactl")
        .args(&args[2..])
        .env_clear()
        .exec()
        .into())
}
