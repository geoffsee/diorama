//! Synthetic children, exclusively for the owned disposable PID namespace.
use diorama_dev::Result;
use std::{
    fs,
    io::Write,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

fn record(root: &Path, name: &str, value: impl ToString + Copy) -> Result<()> {
    let temporary = root.join(format!("{name}.new"));
    fs::write(&temporary, value.to_string())?;
    fs::rename(temporary, root.join(name))?;
    Ok(())
}
fn disposable() -> Result<()> {
    if cfg!(target_os = "linux")
        && [
            "DIORAMA_PROCESS_DISPOSABLE",
            "DIORAMA_OUTPUT_DISPOSABLE",
            "DIORAMA_SIGNAL_DISPOSABLE",
        ]
        .iter()
        .any(|key| std::env::var(key).as_deref() == Ok("1"))
    {
        Ok(())
    } else {
        Err("fixture requires explicit disposable Linux environment".into())
    }
}
fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
pub(super) fn process(mode: &str, root: &Path) -> Result<u8> {
    disposable()?;
    fs::create_dir_all(root)?;
    if mode == "early" {
        return Ok(17);
    }
    if mode == "oneshot" {
        return Ok(0);
    }
    if ![
        "family",
        "leader-exits-first",
        "delayed",
        "ignore",
        "descendant",
        "term-error",
        "steady",
        "sentinel",
    ]
    .contains(&mode)
    {
        return Err("unknown process fixture mode".into());
    }
    runtime()?.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut child = if ["family", "leader-exits-first"].contains(&mode) {
            let child = Command::new(std::env::current_exe()?)
                .arg("process-child")
                .arg(if mode == "family" {
                    "descendant"
                } else {
                    "ignore"
                })
                .arg(root.join("child"))
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(3);
            while !root.join("child/ready").exists() {
                if Instant::now() >= deadline {
                    return Err("descendant readiness timeout".into());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Some(child)
        } else {
            None
        };
        if mode == "leader-exits-first" {
            return Ok(17);
        }
        if mode == "delayed" {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        record(root, "ready", std::process::id())?;
        let mut count = 0u64;
        loop {
            count += 1;
            record(root, "heartbeat", count)?;
            match tokio::time::timeout(Duration::from_millis(20), term.recv()).await {
                Ok(Some(())) => {
                    record(root, "term", "received")?;
                    if mode != "ignore" {
                        break;
                    }
                },
                Err(_) => {},
                Ok(None) => return Err("termination signal channel closed".into()),
            }
        }
        if let Some(child) = &mut child {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Some(status) = child.try_wait()? {
                    record(
                        root,
                        "descendant_reaped",
                        status.code().ok_or("descendant signalled")?,
                    )?;
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("descendant reap timeout".into());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        record(root, "stopped", "graceful")?;
        Ok(if mode == "term-error" { 17 } else { 0 })
    })
}

pub(super) fn output(mode: &str, root: &Path) -> Result<u8> {
    // This finite byte-only mode is safe for the host launcher regression too.
    if mode == "merged" {
        std::io::stdout().write_all(b"out\xff")?;
        std::io::stdout().flush()?;
        std::io::stderr().write_all(b"err\0")?;
        return Ok(0);
    }
    disposable()?;
    match mode {
        "exact" | "overflow" => {
            std::io::stdout().write_all(&vec![b'x'; if mode == "exact" { 64 } else { 65 }])?;
        },
        "simultaneous" => {
            let worker = std::thread::spawn(|| std::io::stderr().write_all(&[b'b'; 1000]));
            std::io::stdout().write_all(&[b'a'; 1000])?;
            worker.join().map_err(|_| "output thread panic")??;
        },
        "flood" => loop {
            std::io::stdout().write_all(&[b'x'; 4096])?;
        },
        "stop" | "timeout" | "abort" | "probe-failure" => runtime()?.block_on(async {
            let mut signal =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            std::io::stdout().write_all(b"prefix")?;
            std::io::stdout().flush()?;
            fs::write(root.join("ready"), "ready")?;
            signal.recv().await.ok_or("termination signal closed")?;
            std::io::stderr().write_all(b"term-handler-output")?;
            fs::write(root.join("term"), "handled")?;
            Ok::<_, diorama_dev::Error>(())
        })?,
        "descendant" | "escaped" => {
            let _child = Command::new(std::env::current_exe()?)
                .args(["output-writer", mode])
                .arg(root)
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(3);
            while !root.join("descendant").exists() {
                if Instant::now() >= deadline {
                    return Err("writer readiness timeout".into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            std::io::stdout().write_all(b"leader")?;
        },
        "empty" => {},
        _ => return Err("unknown output mode".into()),
    }
    Ok(0)
}
pub(super) fn writer(mode: &str, root: &Path) -> Result<u8> {
    disposable()?;
    if mode == "escaped" {
        rustix::process::setsid()?;
    }
    fs::write(root.join("descendant"), std::process::id().to_string())?;
    std::thread::sleep(Duration::from_secs(2));
    Ok(0)
}
