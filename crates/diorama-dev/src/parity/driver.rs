//! Linux PID-1 driver for the isolated, dedicated artifact UID.
use super::{
    Result,
    contract::{self, Artifact, Case, Suite},
    process::{Cancellation, OwnedChild, exit_code},
    require,
};
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

fn stream_filename(path: &Path) -> Result<Value> {
    Ok(json!(
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or("UTF-8 stream filename required")?
    ))
}

fn escaped() -> Result<Vec<u32>> {
    let mut found = Vec::new();
    let mut entries = 0usize;
    for entry in fs::read_dir("/proc")? {
        entries += 1;
        require(entries <= 65536, "proc entry bound")?;
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let bytes = match super::read(&entry.path().join("status"), 65536) {
            Ok(bytes) => bytes,
            Err(error) if !entry.path().exists() => {
                let _ = error;
                continue;
            },
            Err(error) => return Err(error),
        };
        let text = String::from_utf8(bytes)?;
        if text
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|l| l.split_whitespace().next())
            == Some("65532")
        {
            found.push(pid);
            if let Some(pid) = i32::try_from(pid)
                .ok()
                .and_then(rustix::process::Pid::from_raw)
            {
                match rustix::process::kill_process(pid, rustix::process::Signal::KILL) {
                    Ok(()) | Err(rustix::io::Errno::SRCH) => {},
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until {
        match rustix::process::wait(rustix::process::WaitOptions::NOHANG) {
            Ok(Some(_)) => {},
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(rustix::io::Errno::CHILD) => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(found)
}
#[allow(
    clippy::too_many_lines,
    reason = "Keep child ownership and all error settlement in one scope"
)]
fn execute(case: &Case, index: usize, output: &Path, cancellation: &Cancellation) -> Value {
    if case.privilege != "none" {
        return json!({"id":case.id,"argv":case.argv,"status":"gap","reason":"privileged cases require the explicit disposable Linux VM adapter"});
    }
    let began = Instant::now();
    let mut report = json!({"id":case.id,"argv":case.argv,"status":"failed"});
    let mut owner = None;
    let mut errors = Vec::new();
    let outcome = (|| -> Result<()> {
        require(
            !cancellation.requested(),
            "cancelled before artifact launch",
        )?;
        let out = output.join(format!("{index:03}.stdout"));
        let err = output.join(format!("{index:03}.stderr"));
        let stdout = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&out)?;
        let stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&err)?;
        let mut request = tempfile::tempfile()?;
        request.write_all(case.stdin.as_bytes())?;
        request.seek(SeekFrom::Start(0))?;
        let mut environment = std::collections::BTreeMap::from([
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            ("HOME".into(), "/tmp".into()),
            ("LANG".into(), "C.UTF-8".into()),
        ]);
        environment.extend(case.env.clone());
        let argv = contract::fixture_argv(
            case,
            &std::path::PathBuf::from(format!("/fixtures/{index:03}")),
        )?
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>();
        owner = Some(OwnedChild::spawn(super::process::SpawnRequest {
            program: Path::new("/artifact/executable"),
            argv: &argv,
            environment: Some(&environment),
            current_directory: Some(Path::new("/tmp")),
            input: request,
            stdout: stdout.into(),
            stderr: stderr.into(),
            byte_limit: 256 * 1024,
            uid: Some(65532),
            launcher: None,
        })?);
        let child = owner.as_mut().ok_or("missing child owner")?;
        let mut timeout = false;
        let mut cancelled = false;
        while child.poll()?.is_none() {
            timeout = began.elapsed() >= Duration::from_secs(case.timeout_seconds);
            cancelled = cancellation.requested();
            if timeout || cancelled {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.settle(&mut errors);
        let code = child.poll()?.map_or(-1, exit_code);
        let outbytes = super::read(&out, 256 * 1024)?;
        let errbytes = super::read(&err, 256 * 1024)?;
        let mut failures = contract::assess(
            case,
            code,
            &String::from_utf8_lossy(&outbytes),
            &String::from_utf8_lossy(&errbytes),
        );
        if timeout {
            failures.push("command exceeded its timeout".into());
        }
        if cancelled {
            failures.push("command cancelled".into());
        }
        if outbytes.len() >= 256 * 1024 || errbytes.len() >= 256 * 1024 {
            failures.push("command reached its 256 KiB output limit".into());
        }
        report["timeout"] = json!(timeout);
        report["cancelled"] = json!(cancelled);
        report["exit_code"] = json!(code);
        report["failures"] = json!(failures);
        report["stdout_file"] = stream_filename(&out)?;
        report["stderr_file"] = stream_filename(&err)?;
        report["stdout_sha256"] = json!(diorama_dev::sha256(&outbytes));
        report["stderr_sha256"] = json!(diorama_dev::sha256(&errbytes));
        if failures.is_empty() && errors.is_empty() {
            report["status"] = json!("passed");
        }
        Ok(())
    })();
    if let Err(error) = outcome {
        errors.push(error.to_string());
    }
    if let Some(child) = owner.as_mut() {
        // Already-settled owners do not signal; on error this completes retained cleanup.
        let absent = child.group_absent().unwrap_or(false);
        if !absent {
            child.settle(&mut errors);
        }
        report["owned_process_group_absent"] = json!(child.group_absent().unwrap_or(false));
    }
    match escaped() {
        Ok(pids) => {
            report["artifact_uid_inventory_confirmed"] = json!(true);
            if !pids.is_empty() {
                report["remaining_artifact_pids"] = json!(pids);
                errors.push("escaped artifact descendants found in dedicated UID".into());
            }
        },
        Err(e) => {
            report["artifact_uid_inventory_confirmed"] = json!(false);
            errors.push(format!("artifact UID settlement: {e}"));
        },
    }
    if !errors.is_empty() {
        report["status"] = json!("failed");
        report["errors"] = json!(errors);
    }
    report["duration_seconds"] = json!(began.elapsed().as_secs_f64());
    report
}
pub(crate) fn run(cancellation: &Cancellation) -> Result<u8> {
    require(
        cfg!(target_os = "linux")
            && std::process::id() == 1
            && rustix::process::getuid().as_raw() == 0,
        "driver requires root PID 1 in an explicitly isolated container",
    )?;
    let output = Path::new("/evidence");
    let mut report = json!({"schema_version":1,"status":"failed","cases":[],"unsupported_capabilities":["privileged-runtime","cluster-lifecycle","conformance"],"environment":{"system":std::env::consts::OS,"architecture":std::env::consts::ARCH,"driver_uid":0,"artifact_uid":65532},"driver_sha256":super::digest(&std::env::current_exe()?,false)?});
    let result = (|| -> Result<()> {
        let artifact: Artifact =
            serde_json::from_value(super::json_file(Path::new("/artifact/artifact.json"))?)?;
        let suite: Suite =
            serde_json::from_value(super::json_file(Path::new("/artifact/suite.json"))?)?;
        contract::validate(&artifact, &suite)?;
        report["artifact"] = serde_json::to_value(&artifact)?;
        report["suite_id"] = json!(suite.id);
        report["suite_sha256"] = json!(super::digest(Path::new("/artifact/suite.json"), false)?);
        require(
            super::digest(Path::new("/artifact/executable"), false)? == artifact.sha256,
            "runtime artifact digest mismatch",
        )?;
        require(
            std::env::var("PARITY_INJECT_FAILURE").as_deref() != Ok("setup"),
            "intentional setup failure after isolated resources exist",
        )?;
        let mut cases = Vec::new();
        for (index, case) in suite.cases.iter().enumerate() {
            let outcome = execute(case, index, output, cancellation);
            let stop = outcome.get("remaining_artifact_pids").is_some()
                || outcome["owned_process_group_absent"] == false
                || outcome["artifact_uid_inventory_confirmed"] == false
                || cancellation.requested();
            cases.push(outcome);
            if stop {
                report["unexecuted_case_ids"] = json!(
                    suite.cases[index + 1..]
                        .iter()
                        .map(|c| &c.id)
                        .collect::<Vec<_>>()
                );
                break;
            }
        }
        report["cases"] = json!(cases);
        require(
            !cancellation.requested(),
            "cancelled through driver settlement",
        )?;
        require(
            std::env::var("PARITY_INJECT_FAILURE").as_deref() != Ok("test"),
            "intentional test failure after diagnostic capture",
        )?;
        report["status"] = json!(if cases.iter().any(|c| c["status"] == "failed") {
            "failed"
        } else if cases.iter().any(|c| c["status"] == "gap") {
            "gaps"
        } else {
            "passed"
        });
        Ok(())
    })();
    if let Err(error) = result {
        report["error"] = json!(error.to_string());
        report["status"] = json!("failed");
    }
    super::write_json(&output.join("result.json"), &report, true)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(match report["status"].as_str() {
        Some("passed") => 0,
        Some("gaps") => 2,
        _ => 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    #[test]
    fn stream_filenames_are_json_strings_without_os_tags() -> Result<()> {
        for name in ["000.stdout", "038.stderr"] {
            let value = stream_filename(&Path::new("/evidence").join(name))?;
            assert_eq!(value.as_str(), Some(name));
            assert_eq!(serde_json::to_string(&value)?, format!("\"{name}\""));
        }
        assert!(stream_filename(Path::new("/")).is_err());
        assert!(stream_filename(Path::new(std::ffi::OsStr::from_bytes(b"bad-\xff"))).is_err());
        Ok(())
    }

    #[test]
    fn privileged_case_returns_gap_before_any_process_or_file_effect() {
        let case: Case = serde_json::from_value(
            json!({"id":"privileged","argv":[],"expect":{"exit_code":0},"privilege":"privileged"}),
        )
        .unwrap();
        let result = execute(
            &case,
            0,
            Path::new("/path/that/must/not/exist"),
            &Cancellation::default(),
        );
        assert_eq!(result["status"], "gap");
        assert!(result.get("exit_code").is_none());
    }
}
