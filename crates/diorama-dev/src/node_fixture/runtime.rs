use super::common::{Result, read, require};
use std::{
    fs,
    io::Write,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
pub(super) fn probe(args: &[std::ffi::OsString]) -> Result<u8> {
    let mode = String::from_utf8(read(Path::new("/tmp/probe-mode"), 64)?)?;
    fs::write("/tmp/probe-started", "started")?;
    require(
        args == [std::ffi::OsString::from("--version")]
            && std::env::current_dir()? == Path::new("/")
            && std::env::var("PATH").as_deref() == Ok("/usr/sbin:/usr/bin:/sbin:/bin"),
        "fixed probe invocation",
    )?;
    require(
        std::env::var_os("PRIVATE_SENTINEL").is_none(),
        "probe environment isolation",
    )?;
    match mode.as_str() {
        "nft" => std::io::stderr().write_all(b"iptables v1.8 (nf_tables)\n")?,
        "legacy" => std::io::stdout().write_all(b"iptables v1.8 (legacy)\n")?,
        "invalid-utf8" => std::io::stdout().write_all(b"\xff(nf_tables)")?,
        "nonzero" => {
            std::io::stdout().write_all(b"(nf_tables)")?;
            return Ok(17);
        },
        "overflow" => std::io::stdout().write_all(&[b'x'; 4097])?,
        "deadline" => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let _ignore =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                tokio::time::sleep(Duration::from_mins(1)).await;
                Ok::<_, diorama_dev::Error>(())
            })?;
        },
        "cancel" => std::thread::sleep(Duration::from_mins(1)),
        "held" => {
            let _child = Command::new("/node-fixture").arg("held-writer").spawn()?;
            let deadline = Instant::now() + Duration::from_secs(3);
            while !Path::new("/tmp/held-ready").exists() {
                require(Instant::now() < deadline, "held writer ready")?;
                std::thread::sleep(Duration::from_millis(1));
            }
            std::io::stdout().write_all(b"(nf_tables)")?;
        },
        "empty" => {},
        _ => return Err("unknown probe fixture mode".into()),
    }
    Ok(0)
}
pub(super) fn held_writer() -> Result<u8> {
    require(cfg!(target_os = "linux"), "Linux disposable fixture")?;
    rustix::process::setsid()?;
    fs::write("/tmp/held-ready", "ready")?;
    std::thread::sleep(Duration::from_secs(2));
    Ok(0)
}
pub(super) fn consumer(cancellation: &crate::parity::process::Cancellation) -> Result<()> {
    use crate::parity::process::{CommandRequest, Commands, OutputMode};
    let marker = Path::new("/tmp/probe-started");
    match fs::remove_file(marker) {
        Ok(()) => {},
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => return Err(e.into()),
    }
    let directory = tempfile::tempdir_in("/tmp")?;
    let result = (|| {
        for (case, args, expected) in [
            ("help", vec!["--help"], 0),
            ("version", vec!["--version"], 0),
            ("print", vec!["--print-config"], 0),
            ("blocked", vec![], 1),
        ] {
            let argv = std::iter::once("/out/assess_host")
                .chain(args)
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>();
            let result = Commands {
                output: directory.path().into(),
                cancellation: cancellation.clone(),
            }
            .capture(CommandRequest {
                label: case,
                argv: &argv,
                timeout: Duration::from_secs(5),
                input: b"",
                required: false,
                byte_limit: 65536,
                mode: OutputMode::Merged,
                environment: None,
                current_directory: None,
                launcher: None,
            })?;
            require(
                result.code == expected && !marker.exists(),
                "consumer effect boundary",
            )?;
            if case == "blocked" {
                require(
                    result.stdout_bytes.windows(7).any(|s| s == b"Blocked"),
                    "actual nonroot blocker",
                )?;
            }
            println!("DIORAMA_NODE_CONSUMER case={case} exit={expected} probe_absent=true");
        }
        Ok(())
    })();
    if result.as_ref().is_err_and(|e: &diorama_dev::Error| {
        e.downcast_ref::<crate::parity::process::CommandFailure>()
            .is_some_and(|f| !f.cleanup_complete)
    }) {
        eprintln!(
            "unsettled consumer; retained {}",
            directory.keep().display()
        );
    }
    result
}
pub(super) fn namespace() -> Result<()> {
    let stat = String::from_utf8(read(Path::new("/proc/self/stat"), 8192)?)?;
    let parent = stat
        .rsplit_once(") ")
        .ok_or("proc stat")?
        .1
        .split_whitespace()
        .nth(1)
        .ok_or("parent")?
        .parse::<u32>()?;
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc")? {
        if let Some(pid) = entry?
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        {
            pids.push(pid);
        }
        require(pids.len() <= 96, "namespace process bound")?;
    }
    pids.sort_unstable();
    println!(
        "DIORAMA_NAMESPACE {}",
        serde_json::json!({"init":1,"shell":parent,"helper":std::process::id(),"processes":pids})
    );
    Ok(())
}
