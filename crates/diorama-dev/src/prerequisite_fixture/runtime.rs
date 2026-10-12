//! Linux-only synthetic effects within explicitly owned disposable chroots.
use super::{Path, Result, require};
use crate::parity::process::{OwnedChild, SpawnRequest};
use rustix::process::{Pid, Signal};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs::{self, File},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
pub(super) fn enter(args: &[OsString]) -> Result<u8> {
    require(
        Path::new("/.dockerenv").is_file() && rustix::process::getuid().is_root(),
        "disposable container entry required",
    )?;
    require(args.len() >= 3, "chroot arguments")?;
    let root = Path::new(&args[0]);
    require(
        root.starts_with("/tmp")
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("diorama-preparation-")),
        "owned chroot path",
    )?;
    let uid = args[1].to_str().ok_or("uid UTF8")?.parse::<u32>()?;
    require([0, 65534].contains(&uid), "fixture uid")?;
    rustix::process::chroot(root)?;
    std::env::set_current_dir("/")?;
    if uid != 0 {
        rustix::thread::set_thread_uid(rustix::process::Uid::from_raw(uid))?;
    }
    Err(Command::new("/dioramactl")
        .args(&args[2..])
        .env_clear()
        .exec()
        .into())
}
fn setup(root: &Path, mode: &str) -> Result<()> {
    fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    for path in ["sbin", "dev", "proc/net", "sys/fs/cgroup", "etc"] {
        fs::create_dir_all(root.join(path))?;
    }
    for (source, destination) in [
        ("/dioramactl", "dioramactl"),
        ("/fixture-command", "sbin/apk"),
        ("/fixture-command", "sbin/rc-update"),
        ("/fixture-command", "sbin/rc-service"),
    ] {
        fs::copy(source, root.join(destination))?;
        fs::set_permissions(root.join(destination), fs::Permissions::from_mode(0o755))?;
    }
    for (path, text) in [
        ("dev/null", ""),
        ("etc/alpine-release", "3.24.2\n"),
        ("proc/version", "Linux fixture\n"),
        ("proc/modules", "xt_comment 1 0 - Live 0x0\n"),
        ("proc/net/ip_tables_matches", "comment\n"),
        ("mode", mode),
    ] {
        fs::write(root.join(path), text)?;
    }
    Ok(())
}
fn invoke(root: &Path, opt_in: bool, send: Option<Signal>, uid: u32) -> Result<Value> {
    let logs = tempfile::tempdir_in("/tmp")?;
    let mut args = vec![
        "__enter-chroot".into(),
        root.into(),
        uid.to_string().into(),
        "check".into(),
    ];
    if opt_in {
        args.push("--install-prereqs".into());
    }
    let executable = std::env::current_exe()?;
    let mut owner = OwnedChild::spawn(SpawnRequest {
        program: &executable,
        argv: &args,
        environment: Some(&std::collections::BTreeMap::new()),
        current_directory: None,
        input: File::open("/dev/null")?,
        stdout: Stdio::from(File::create(logs.path().join("stdout"))?),
        stderr: Stdio::from(File::create(logs.path().join("stderr"))?),
        byte_limit: 65536,
        uid: None,
        launcher: None,
    })?;
    let mut signalled = false;
    let mut active = None;
    let operation = (|| -> Result<i32> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = owner.poll()? {
                return status
                    .code()
                    .ok_or_else(|| "CLI killed instead of handling signal".into());
            }
            require(Instant::now() < deadline, "CLI deadline")?;
            require(
                fs::metadata(logs.path().join("stdout"))?.len()
                    + fs::metadata(logs.path().join("stderr"))?.len()
                    <= 65536,
                "CLI output limit",
            )?;
            if let Some(signal) = send
                && !signalled
                && root.join("active-pid").exists()
            {
                active = Some(
                    String::from_utf8(crate::parity::read(&root.join("active-pid"), 32)?)?
                        .trim()
                        .parse::<i32>()?,
                );
                signal_owned_cli(&mut owner, signal)?;
                signalled = true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    let mut cleanup = Vec::new();
    owner.settle(&mut cleanup);
    if !matches!(owner.group_absent(), Ok(true)) {
        let retained_logs = logs.keep();
        return Err(Box::new(Unsettled {
            owner,
            _logs: retained_logs,
            reason: format!("operation {operation:?}; cleanup {cleanup:?}"),
        }));
    }
    require(cleanup.is_empty(), "CLI cleanup failed")?;
    require(
        fs::metadata(logs.path().join("stdout"))?.len()
            + fs::metadata(logs.path().join("stderr"))?.len()
            <= 65536,
        "final combined CLI output limit",
    )?;
    let code = operation?;
    if send.is_some() {
        require(signalled, "active child observed before signal")?;
        let pid = Pid::from_raw(active.ok_or("active PID missing")?).ok_or("active PID")?;
        require(
            matches!(
                rustix::process::test_kill_process(pid),
                Err(rustix::io::Errno::SRCH)
            ),
            "owned command survives CLI",
        )?;
    }
    let actions = if root.join("actions").exists() {
        String::from_utf8(crate::parity::read(&root.join("actions"), 65536)?)?
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    } else {
        vec![]
    };
    Ok(
        json!({"exit":code,"actions":actions,"signal_sent":send.map(Signal::as_raw),"owned_child_absent":send.is_some(),"stdout":String::from_utf8(crate::parity::read(&logs.path().join("stdout"),65536)?)?,"stderr":String::from_utf8(crate::parity::read(&logs.path().join("stderr"),65536)?)?}),
    )
}
fn signal_owned_cli(owner: &mut OwnedChild, signal: Signal) -> Result<()> {
    // The sole waiter retains this unreaped child, so its PID cannot be reused.
    let pid = Pid::from_raw(i32::try_from(owner.pid())?).ok_or("CLI PID")?;
    rustix::process::kill_process(pid, signal)?;
    std::thread::sleep(Duration::from_millis(10));
    if owner.poll()?.is_none() {
        let alternate = if signal == Signal::INT {
            Signal::TERM
        } else {
            Signal::INT
        };
        rustix::process::kill_process(pid, alternate)?;
    }
    Ok(())
}
#[derive(Debug)]
struct Unsettled {
    owner: OwnedChild,
    _logs: std::path::PathBuf,
    reason: String,
}
impl std::fmt::Display for Unsettled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "uncertain CLI owner {}: {}",
            self.owner.pid(),
            self.reason
        )
    }
}
impl std::error::Error for Unsettled {}
pub(super) fn run() -> Result<u8> {
    require(
        Path::new("/.dockerenv").exists()
            && Path::new("/fixture-command").is_file()
            && rustix::process::getuid().is_root(),
        "explicit disposable fixture container required",
    )?;
    let mut cases = vec![
        ("opt_out".to_owned(), "", false, None, 0),
        ("prepare".into(), "", true, None, 0),
        ("no_effect_success".into(), "noop", true, None, 0),
        ("register_failure".into(), "fail-update", true, None, 0),
        ("nonroot".into(), "", true, None, 65534),
    ];
    cases.extend((0..20).map(|i| {
        (
            format!("signal_{i}"),
            "hold",
            true,
            Some(if i % 2 == 0 {
                Signal::INT
            } else {
                Signal::TERM
            }),
            0,
        )
    }));
    let mut rows = Vec::new();
    for (name, mode, optin, send, uid) in cases {
        let root = tempfile::Builder::new()
            .prefix("diorama-preparation-")
            .tempdir_in("/tmp")?;
        setup(root.path(), mode)?;
        let result = invoke(root.path(), optin, send, uid);
        if result
            .as_ref()
            .err()
            .is_some_and(|error| error.downcast_ref::<Unsettled>().is_some())
        {
            let _retained = root.keep();
            return result.map(|_| 1);
        }
        let mut row = result?;
        row["name"] = json!(name);
        rows.push(row);
        if name == "prepare" {
            let result = invoke(root.path(), true, None, 0);
            if result
                .as_ref()
                .err()
                .is_some_and(|error| error.downcast_ref::<Unsettled>().is_some())
            {
                let _retained = root.keep();
                return result.map(|_| 1);
            }
            let mut repeat = result?;
            repeat["name"] = json!("repeat");
            rows.push(repeat);
        }
    }
    println!(
        "DIORAMA_PREPARATION {}",
        serde_json::to_string(&json!({"cases":rows}))?
    );
    Ok(0)
}
