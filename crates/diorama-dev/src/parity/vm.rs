//! Explicitly authorized disposable HVF guest. No system-wide process discovery.
use super::{
    Options, Result,
    contract::{self, Artifact, Suite},
    lifecycle,
    process::{Cancellation, CommandFailure, Commands, OwnedChild},
    require,
};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
const LIMIT: u64 = 256 * 1024;
const CONSOLE_LIMIT: usize = 1024 * 1024;

#[derive(Debug)]
pub(crate) struct Console {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<bool>>>,
}
impl Console {
    pub(crate) fn start(mut stream: UnixStream, path: &Path) -> Result<Self> {
        stream.set_nonblocking(true)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::Builder::new()
            .name("diorama-vm-console".into())
            .spawn(move || {
                let mut stored = 0;
                let mut truncated = false;
                let mut buffer = [0; 4096];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            let room = (CONSOLE_LIMIT - stored).min(n);
                            file.write_all(&buffer[..room])?;
                            stored += room;
                            truncated |= n > room;
                        },
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && worker_stop.load(Ordering::Acquire) =>
                        {
                            break;
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {},
                        Err(e) => return Err(e.into()),
                    }
                }
                file.flush()?;
                Ok(truncated)
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
    pub(crate) fn finish(&mut self) -> Result<bool> {
        self.stop.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(5);
        let worker = self.worker.as_ref().ok_or("console already joined")?;
        while !worker.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        require(
            worker.is_finished(),
            "console reader did not finish; reader ownership retained",
        )?;
        self.worker
            .take()
            .ok_or("console owner missing")?
            .join()
            .map_err(|_| "console reader panicked")?
    }
}
#[derive(Debug)]
struct RetainedVm {
    commands: Vec<CommandFailure>,
    owner: Option<OwnedChild>,
    console: Option<Console>,
}
impl std::fmt::Display for RetainedVm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VM cleanup uncertain: {} command owners, VM owner {}, console owner {} retained",
            self.commands.len(),
            self.owner.is_some(),
            self.console.is_some()
        )
    }
}
impl std::error::Error for RetainedVm {}
fn retain_error(
    error: diorama_dev::Error,
    errors: &mut Vec<String>,
    retained: &mut Vec<CommandFailure>,
) {
    errors.push(error.to_string());
    if let Ok(failure) = error.downcast::<CommandFailure>()
        && !failure.cleanup_complete
    {
        retained.push(*failure);
    }
}
pub(crate) fn executable(name: &str) -> Result<PathBuf> {
    for directory in std::env::split_paths(&std::env::var_os("PATH").ok_or("PATH missing")?) {
        let path = directory.join(name);
        if path.is_file() && path.metadata()?.permissions().mode() & 0o111 != 0 {
            return Ok(path.canonicalize()?);
        }
    }
    Err(format!("missing required tool: {name}").into())
}
fn invoke(
    commands: &Commands,
    label: &str,
    argv: &[OsString],
    seconds: u64,
    required: bool,
) -> Result<super::process::CommandResult> {
    commands.run(
        label,
        argv,
        Duration::from_secs(seconds),
        b"",
        required,
        LIMIT,
    )
}
fn remote(ssh: &[OsString], command: &str) -> Vec<OsString> {
    let mut argv = ssh.to_vec();
    argv.push(command.into());
    argv
}
pub(crate) fn qmp_powerdown(path: &Path) -> Result<()> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let greeting = qmp_message(&mut reader)?;
    require(greeting.get("QMP").is_some(), "invalid QMP greeting")?;
    stream.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
    let acknowledgment = qmp_message(&mut reader)?;
    require(
        acknowledgment.get("return").is_some(),
        "QMP capabilities rejected",
    )?;
    stream.write_all(b"{\"execute\":\"system_powerdown\"}\n")?;
    Ok(())
}
fn qmp_message(reader: &mut impl BufRead) -> Result<Value> {
    let mut bytes = Vec::new();
    reader.take(4097).read_until(b'\n', &mut bytes)?;
    require(
        bytes.len() <= 4096 && bytes.last() == Some(&b'\n'),
        "bounded complete QMP frame required",
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn cached_image(commands: &Commands, cache: &Path, inputs: &Value) -> Result<PathBuf> {
    require(!cache.is_symlink(), "cache directory must not be a symlink")?;
    fs::create_dir_all(cache)?;
    let path = cache.join("debian-12-genericcloud-arm64-20260923-2610.qcow2");
    require(
        !path.is_symlink(),
        "cloud image cache must not be a symlink",
    )?;
    let expected = inputs["image"]["sha512"]
        .as_str()
        .ok_or("image digest missing")?;
    require(
        contract::hexadecimal(expected, 128),
        "invalid pinned SHA512",
    )?;
    if !path.exists() {
        let partial = tempfile::NamedTempFile::new_in(cache)?;
        let argv = vec![
            executable("curl")?.into(),
            "--fail".into(),
            "--location".into(),
            "--proto".into(),
            "=https".into(),
            "--max-time".into(),
            "600".into(),
            "--max-filesize".into(),
            "1073741824".into(),
            "--output".into(),
            partial.path().into(),
            inputs["image"]["url"]
                .as_str()
                .ok_or("image URL missing")?
                .into(),
        ];
        let downloaded = commands.run(
            "image-download",
            &argv,
            Duration::from_secs(610),
            b"",
            true,
            LIMIT,
        );
        if let Err(error) = downloaded {
            if error
                .downcast_ref::<CommandFailure>()
                .is_some_and(|failure| !failure.cleanup_complete)
            {
                let _ = partial.keep()?;
            }
            return Err(error);
        }
        publish_download(partial, &path, expected)?;
    }
    require(
        super::digest(&path, true)? == expected,
        "cached image SHA512 mismatch",
    )?;
    Ok(path.canonicalize()?)
}
fn publish_download(
    partial: tempfile::NamedTempFile,
    destination: &Path,
    expected: &str,
) -> Result<()> {
    require(
        super::digest(partial.path(), true)? == expected,
        "download image SHA512 mismatch",
    )?;
    partial.persist_noclobber(destination)?;
    Ok(())
}
fn cases(suite: &Suite, commands: &Commands, ssh: &[OsString], report: &mut Value) -> Result<()> {
    execute_cases(suite, ssh, report, |label, argv, timeout, input| {
        commands.run(label, argv, timeout, input, false, LIMIT)
    })
}
fn execute_cases(
    suite: &Suite,
    ssh: &[OsString],
    report: &mut Value,
    mut invoke_case: impl FnMut(
        &str,
        &[OsString],
        Duration,
        &[u8],
    ) -> Result<super::process::CommandResult>,
) -> Result<()> {
    for (index, case) in suite.cases.iter().enumerate() {
        let started = Instant::now();
        let mut env = std::collections::BTreeMap::from([
            (
                "PATH".to_owned(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
            ),
            ("HOME".into(), "/root".into()),
            ("LANG".into(), "C.UTF-8".into()),
        ]);
        env.extend(case.env.clone());
        let mut argv = vec!["env".to_owned(), "-i".into()];
        argv.extend(env.iter().map(|(k, v)| format!("{k}={v}")));
        argv.extend([
            "timeout".into(),
            "--signal=KILL".into(),
            case.timeout_seconds.to_string(),
            "/opt/diorama/artifact".into(),
        ]);
        argv.extend(contract::fixture_argv(
            case,
            &PathBuf::from(format!("/fixtures/{index:03}")),
        )?);
        let uid = if case.privilege == "none" {
            argv.splice(
                0..0,
                [
                    "runuser".into(),
                    "--user".into(),
                    "nobody".into(),
                    "--".into(),
                ],
            );
            65534
        } else {
            0
        };
        let command = argv
            .iter()
            .map(|a| super::quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        let result = invoke_case(
            &format!("case-{index:03}"),
            &remote(ssh, &command),
            Duration::from_secs(case.timeout_seconds + 10),
            case.stdin.as_bytes(),
        );
        match result {
            Ok(result) => {
                let mut failures =
                    contract::assess(case, result.code, &result.stdout, &result.stderr);
                let timed_out = matches!(result.code, 124 | 137);
                if timed_out {
                    failures.push(
                        "command reached reserved timeout/SIGKILL status; aborting VM suite".into(),
                    );
                }
                report["cases"].as_array_mut().ok_or("case report invariant")?.push(json!({"id":case.id,"status":if failures.is_empty(){"passed"}else{"failed"},"exit_code":result.code,"failures":failures,"guest_uid":uid,"timed_out":timed_out,"duration_seconds":started.elapsed().as_secs_f64(),"requested_privilege":case.privilege,"stdout_sha256":result.receipt["stdout_sha256"],"stderr_sha256":result.receipt["stderr_sha256"]}));
                if timed_out {
                    report["unexecuted_case_ids"] = json!(
                        suite.cases[index + 1..]
                            .iter()
                            .map(|c| &c.id)
                            .collect::<Vec<_>>()
                    );
                    break;
                }
            },
            Err(error) => {
                report["cases"].as_array_mut().ok_or("case report invariant")?.push(json!({"id":case.id,"status":"failed","error":error.to_string(),"duration_seconds":started.elapsed().as_secs_f64()}));
                report["unexecuted_case_ids"] = json!(
                    suite.cases[index + 1..]
                        .iter()
                        .map(|c| &c.id)
                        .collect::<Vec<_>>()
                );
                return Err(error);
            },
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "Explicit sequential VM ownership and settlement; no early return bypasses cleanup"
)]
pub(crate) fn run(options: &Options, cancellation: &Cancellation) -> Result<u8> {
    require(
        options.privileged,
        "VM requires explicit --allow-privileged-vm",
    )?;
    let output = options.path("--output")?;
    fs::create_dir_all(output.parent().ok_or("output parent")?)?;
    fs::create_dir(&output)?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
    let commands = Commands {
        output: output.clone(),
        cancellation: cancellation.clone(),
    };
    let cleanup = Commands {
        output: output.clone(),
        cancellation: Cancellation::default(),
    };
    let mut report = json!({"schema_version":1,"status":"failed","cases":[],"adapter":"qemu-disposable-linux-vm","explicit_privilege_opt_in":true,"unsupported_capabilities":["full-cluster-assets","release-platform-qualification"]});
    let mut errors = Vec::new();
    let mut retained = Vec::new();
    let mut private: Option<PathBuf> = None;
    let mut owner: Option<OwnedChild> = None;
    let mut console: Option<Console> = None;
    let mut ssh = Vec::new();
    let mut qmp = PathBuf::new();
    let operation = (|| -> Result<()> {
        require(
            cfg!(all(target_os = "macos", target_arch = "aarch64")),
            "initial VM adapter requires Darwin arm64 with HVF",
        )?;
        require(!cancellation.requested(), "cancelled before preparation")?;
        let root = options.root()?;
        let artifact_path = options.path("--artifact")?;
        let suite_path = options.path("--suite")?;
        let artifact: Artifact = serde_json::from_value(super::json_file(&artifact_path)?)?;
        let suite: Suite = serde_json::from_value(super::json_file(&suite_path)?)?;
        contract::validate(&artifact, &suite)?;
        let binary = artifact_path
            .parent()
            .ok_or("artifact parent")?
            .join(&artifact.binary)
            .canonicalize()?;
        require(
            super::digest(&binary, false)? == artifact.sha256,
            "artifact digest mismatch",
        )?;
        let inputs_path = root.join("tools/parity/vm/inputs.json");
        let inputs = super::json_file(&inputs_path)?;
        report["artifact"] = serde_json::to_value(&artifact)?;
        report["suite_id"] = json!(suite.id);
        report["suite_sha256"] = json!(super::digest(&suite_path, false)?);
        report["inputs"] = inputs.clone();
        report["source_sha256"] = json!({"inputs.json":super::digest(&inputs_path,false)?,"runner_binary":super::digest(&std::env::current_exe()?,false)?});
        let mut tools = serde_json::Map::new();
        for name in [
            "qemu-system-aarch64",
            "qemu-img",
            "ssh",
            "ssh-keygen",
            "scp",
        ] {
            let path = executable(name)?;
            tools.insert(
                name.into(),
                json!({"path":path,"sha256":super::digest(&path,false)?}),
            );
        }
        report["tools"] = Value::Object(tools);
        let firmware = Path::new("/opt/homebrew/share/qemu/edk2-aarch64-code.fd");
        let vars = Path::new("/opt/homebrew/share/qemu/edk2-arm-vars.fd");
        report["firmware"] = json!({"code_sha256":super::digest(firmware,false)?,"vars_template_sha256":super::digest(vars,false)?});
        report["qemu_version"] = json!(
            invoke(
                &commands,
                "qemu-version",
                &super::args(&["qemu-system-aarch64", "--version"]),
                30,
                true
            )?
            .stdout
        );
        let image = cached_image(&commands, &options.path("--image-cache")?, &inputs)?;
        let directory = tempfile::Builder::new()
            .prefix("diorama-vm-")
            .tempdir_in("/tmp")?
            .keep();
        private = Some(directory.clone());
        report["owned_temporary_directory"] = json!(directory);
        fs::copy(vars, directory.join("vars.fd"))?;
        invoke(
            &commands,
            "overlay",
            &[
                "qemu-img".into(),
                "create".into(),
                "-f".into(),
                "qcow2".into(),
                "-F".into(),
                "qcow2".into(),
                "-b".into(),
                image.into(),
                directory.join("disk.qcow2").into(),
                "8G".into(),
            ],
            30,
            true,
        )?;
        for name in ["client", "host"] {
            invoke(
                &commands,
                &format!("key-{name}"),
                &[
                    "ssh-keygen".into(),
                    "-q".into(),
                    "-t".into(),
                    "ed25519".into(),
                    "-N".into(),
                    "".into(),
                    "-C".into(),
                    "diorama-disposable".into(),
                    "-f".into(),
                    directory.join(name).into(),
                ],
                30,
                true,
            )?;
        }
        let host_private = String::from_utf8(super::read(&directory.join("host"), 4096)?)?;
        let host_public = String::from_utf8(super::read(&directory.join("host.pub"), 4096)?)?;
        let client_public = String::from_utf8(super::read(&directory.join("client.pub"), 4096)?)?;
        let mut indented_key = String::new();
        for line in host_private.lines() {
            use std::fmt::Write as _;
            writeln!(&mut indented_key, "    {line}")?;
        }
        let user = format!(
            "#cloud-config\ndisable_root: false\nssh_pwauth: false\nusers:\n  - name: root\n    ssh_authorized_keys:\n      - {}\nssh_keys:\n  ed25519_private: |\n{}  ed25519_public: {}\n",
            client_public.trim(),
            indented_key,
            host_public.trim()
        );
        let metadata = format!(
            "instance-id: diorama-{}\nlocal-hostname: diorama-parity\n",
            diorama_dev::sha256(directory.as_os_str().as_encoded_bytes())
        );
        fs::write(
            directory.join("seed.iso"),
            super::seed::image(user.as_bytes(), metadata.as_bytes())?,
        )?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        report["ssh_forward"] = json!(format!("127.0.0.1:{port}"));
        fs::write(
            directory.join("known_hosts"),
            format!("[127.0.0.1]:{port} {}\n", host_public.trim()),
        )?;
        let mut ssh_options = super::args(&["-F", "/dev/null", "-i"]);
        ssh_options.push(directory.join("client").into());
        for option in [
            "BatchMode=yes".into(),
            "IdentitiesOnly=yes".into(),
            "IdentityAgent=none".into(),
            "GlobalKnownHostsFile=/dev/null".into(),
            "StrictHostKeyChecking=yes".into(),
            format!(
                "UserKnownHostsFile={}",
                directory.join("known_hosts").display()
            ),
            "ConnectTimeout=3".into(),
            "ConnectionAttempts=1".into(),
            "ServerAliveInterval=5".into(),
            "ServerAliveCountMax=2".into(),
        ] {
            ssh_options.push("-o".into());
            ssh_options.push(option.into());
        }
        ssh = vec!["ssh".into()];
        ssh.extend(ssh_options.clone());
        ssh.extend(super::args(&["-p", &port.to_string(), "root@127.0.0.1"]));
        qmp = directory.join("qmp.sock");
        let qemu = super::args(&[
            "qemu-system-aarch64",
            "-machine",
            "virt,accel=hvf",
            "-cpu",
            "host",
            "-smp",
            "2",
            "-m",
            "2048",
            "-display",
            "none",
            "-serial",
            "stdio",
            "-monitor",
            "none",
            "-qmp",
            &format!("unix:{},server=on,wait=off", qmp.display()),
            "-drive",
            &format!(
                "if=pflash,format=raw,readonly=on,file={}",
                firmware.display()
            ),
            "-drive",
            &format!(
                "if=pflash,format=raw,file={}",
                directory.join("vars.fd").display()
            ),
            "-drive",
            &format!(
                "if=virtio,format=qcow2,file={}",
                directory.join("disk.qcow2").display()
            ),
            "-drive",
            &format!(
                "if=virtio,format=raw,readonly=on,file={}",
                directory.join("seed.iso").display()
            ),
            "-netdev",
            &format!("user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:{port}-:22"),
            "-device",
            "virtio-net-pci,netdev=n0",
        ]);
        report["qemu_argv"] = json!(qemu.iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>());
        require(!cancellation.requested(), "cancelled before VM spawn")?;
        let (reader, writer) = UnixStream::pair()?;
        let stderr = writer.try_clone()?;
        owner = Some(OwnedChild::spawn(super::process::SpawnRequest {
            program: Path::new(&qemu[0]),
            argv: &qemu[1..],
            environment: None,
            current_directory: None,
            input: File::open("/dev/null")?,
            stdout: Stdio::from(OwnedFd::from(writer)),
            stderr: Stdio::from(OwnedFd::from(stderr)),
            byte_limit: 16 * 1024 * 1024 * 1024,
            uid: None,
            launcher: None,
        })?);
        report["owned_pid"] = json!(owner.as_ref().ok_or("VM owner invariant")?.pid());
        console = Some(Console::start(reader, &output.join("serial.log"))?);
        let started = Instant::now();
        let mut ready = false;
        let mut attempt = 0usize;
        while started.elapsed() < Duration::from_mins(3) {
            attempt += 1;
            require(
                owner
                    .as_mut()
                    .ok_or("VM owner invariant")?
                    .poll()?
                    .is_none(),
                "QEMU exited during boot",
            )?;
            if invoke(
                &commands,
                &format!("ssh-readiness-{attempt:03}"),
                &remote(&ssh, "true"),
                8,
                false,
            )?
            .code
                == 0
            {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        require(ready, "SSH readiness exceeded 180 seconds")?;
        report["ssh_readiness_seconds"] = json!(started.elapsed().as_secs_f64());
        invoke(
            &commands,
            "cloud-init",
            &remote(&ssh, "cloud-init status --wait"),
            60,
            true,
        )?;
        report["environment"] = json!(
            invoke(
                &commands,
                "environment",
                &remote(
                    &ssh,
                    "uname -a; id; cat /etc/os-release; cat /proc/self/cgroup"
                ),
                30,
                true
            )?
            .stdout
        );
        invoke(
            &commands,
            "privileged-probe",
            &remote(
                &ssh,
                "mkdir -p /mnt/diorama-probe && mount -t tmpfs -o size=1m tmpfs /mnt/diorama-probe && umount /mnt/diorama-probe && rmdir /mnt/diorama-probe",
            ),
            30,
            true,
        )?;
        report["privileged_mount_probe"] = json!("passed");
        require(
            options.injected()? != Some("setup"),
            "intentional setup failure after guest privilege probe",
        )?;
        let mut scp = vec!["scp".into()];
        scp.extend(ssh_options);
        scp.extend(super::args(&["-P", &port.to_string()]));
        let mut copy = scp.clone();
        copy.push(binary.into());
        copy.push("root@127.0.0.1:/tmp/artifact".into());
        invoke(&commands, "copy-artifact", &copy, 60, true)?;
        let observed = invoke(
            &commands,
            "artifact-digest",
            &remote(
                &ssh,
                "mkdir -p /opt/diorama && mv /tmp/artifact /opt/diorama/artifact && chmod 0755 /opt/diorama/artifact && sha256sum /opt/diorama/artifact",
            ),
            30,
            true,
        )?;
        require(
            observed.stdout.split_whitespace().next() == Some(artifact.sha256.as_str()),
            "guest artifact digest mismatch",
        )?;
        if suite.cases.iter().any(|c| !c.files.is_empty()) {
            contract::stage_files(&suite.cases, &directory.join("fixtures"))?;
            scp.push("-r".into());
            scp.push(directory.join("fixtures").into());
            scp.push("root@127.0.0.1:/".into());
            invoke(&commands, "copy-fixtures", &scp, 60, true)?;
            invoke(
                &commands,
                "protect-fixtures",
                &remote(
                    &ssh,
                    "chown -R 0:0 /fixtures && find /fixtures -type d -exec chmod 0555 {} + && find /fixtures -type f -exec chmod 0444 {} +",
                ),
                30,
                true,
            )?;
        }
        cases(&suite, &commands, &ssh, &mut report)?;
        require(
            options.injected()? != Some("test"),
            "intentional test failure after case diagnostics",
        )?;
        if report["cases"]
            .as_array()
            .ok_or("case report invariant")?
            .iter()
            .all(|c| c["status"] == "passed")
        {
            report["status"] = json!("passed");
        }
        Ok(())
    })();
    if let Err(error) = operation {
        retain_error(error, &mut errors, &mut retained);
    }
    let mut absent = owner.is_none() && retained.is_empty();
    if let Some(vm) = owner.as_mut() {
        let settled = lifecycle::settle_vm(
            vm,
            || {
                if !retained.is_empty() {
                    return Err("diagnostics suppressed while command cleanup uncertain".into());
                }
                let diagnostic = invoke(
                    &cleanup,
                    "guest-diagnostics",
                    &remote(
                        &ssh,
                        "journalctl -n 100 --no-pager; ps -eo pid,ppid,uid,comm",
                    ),
                    10,
                    false,
                );
                if let Err(error) = diagnostic {
                    if let Ok(failure) = error.downcast::<CommandFailure>()
                        && !failure.cleanup_complete
                    {
                        retained.push(*failure);
                    }
                    return Err("guest diagnostics failed; inspect command receipt".into());
                }
                Ok(())
            },
            || qmp_powerdown(&qmp),
            &mut errors,
        );
        absent = settled["owned_process_group_absent"] == true && retained.is_empty();
        for (key, value) in settled.as_object().ok_or("settlement report invariant")? {
            report[key] = value.clone();
        }
        vm.settle(&mut errors);
    }
    if let Some(reader) = console.as_mut() {
        match reader.finish() {
            Ok(truncated) => report["serial_log_truncated"] = json!(truncated),
            Err(error) => {
                errors.push(format!("console: {error}"));
                absent = false;
            },
        }
    }
    if cancellation.requested() {
        errors.push("cancelled through VM settlement".into());
    }
    if let Some(private) = private {
        report["owned_temporary_directory_removed"] =
            json!(lifecycle::remove_private(&private, absent, &mut errors));
    }
    if !errors.is_empty() {
        report["status"] = json!("failed");
    }
    report["errors"] = json!(errors);
    report["retained_commands"] = json!(
        retained
            .iter()
            .map(|failure| &failure.receipt)
            .collect::<Vec<_>>()
    );
    let published = super::write_json(&output.join("result.json"), &report, true);
    if !absent {
        return Err(Box::new(RetainedVm {
            commands: retained,
            owner,
            console,
        }));
    }
    published?;
    Ok(u8::from(report["status"] != "passed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn case(code: i32) -> contract::Case {
        serde_json::from_value(json!({"id":"deadline","argv":[],"expect":{"exit_code":code}}))
            .unwrap()
    }
    fn result(code: i32) -> super::super::process::CommandResult {
        super::super::process::CommandResult {
            code,
            stdout: String::new(),
            stderr: String::new(),
            stdout_bytes: vec![],
            stderr_bytes: vec![],
            receipt: json!({}),
        }
    }
    #[test]
    fn reserved_timeout_statuses_abort_even_when_expected() -> Result<()> {
        for code in [124, 137] {
            let suite = Suite {
                schema_version: 1,
                id: "timeouts".into(),
                cases: vec![case(code), case(0)],
            };
            let mut report = json!({"cases":[]});
            let mut calls = 0;
            execute_cases(&suite, &[], &mut report, |_, _, _, _| {
                calls += 1;
                Ok(result(code))
            })?;
            assert_eq!(calls, 1);
            assert_eq!(report["cases"][0]["status"], "failed");
            assert_eq!(report["cases"][0]["timed_out"], true);
            assert_eq!(report["unexecuted_case_ids"], json!(["deadline"]));
        }
        Ok(())
    }
    #[test]
    fn vm_fixture_expansion_and_shell_literals_share_contract() -> Result<()> {
        let mut case = case(0);
        case.files.insert("config.yaml".into(), "synthetic".into());
        case.argv = vec![
            "{fixture:config.yaml}".into(),
            "literal={fixture:config.yaml}".into(),
            "'$(touch /bad)'".into(),
        ];
        let suite = Suite {
            schema_version: 1,
            id: "literal".into(),
            cases: vec![case],
        };
        let mut report = json!({"cases":[]});
        execute_cases(&suite, &[], &mut report, |_, argv, _, _| {
            let command = argv.last().unwrap().to_str().unwrap();
            assert!(command.contains("'/fixtures/000/config.yaml'"));
            assert!(command.contains("'literal={fixture:config.yaml}'"));
            assert!(command.contains(&super::super::quote("'$(touch /bad)'")));
            Ok(result(0))
        })?;
        assert_eq!(report["cases"][0]["status"], "passed");
        Ok(())
    }
    #[test]
    fn cache_publication_is_verified_exclusive_and_rejects_dangling_links() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let destination = dir.path().join("image");
        let mut partial = tempfile::NamedTempFile::new_in(dir.path())?;
        partial.write_all(b"verified")?;
        let digest = super::super::digest(partial.path(), true)?;
        let partial_path = partial.path().to_owned();
        publish_download(partial, &destination, &digest)?;
        assert!(!partial_path.exists());
        assert_eq!(fs::read(&destination)?, b"verified");
        let mut invalid = tempfile::NamedTempFile::new_in(dir.path())?;
        invalid.write_all(b"invalid")?;
        assert!(publish_download(invalid, &destination, &digest).is_err());
        assert_eq!(fs::read(&destination)?, b"verified");
        let link = dir.path().join("link");
        let outside = dir.path().join("outside");
        std::os::unix::fs::symlink(&outside, &link)?;
        let mut valid = tempfile::NamedTempFile::new_in(dir.path())?;
        valid.write_all(b"verified")?;
        assert!(publish_download(valid, &link, &digest).is_err());
        assert!(!outside.exists());
        Ok(())
    }
    #[test]
    fn qmp_messages_are_framed_and_bounded_independently_of_socket_reads() -> Result<()> {
        let mut input = std::io::Cursor::new(b"{\"QMP\":{}}\r\n{\"return\":{}}\r\n");
        assert!(qmp_message(&mut input)?.get("QMP").is_some());
        assert!(qmp_message(&mut input)?.get("return").is_some());
        assert!(qmp_message(&mut std::io::Cursor::new(b"{}")).is_err());
        assert!(qmp_message(&mut std::io::Cursor::new(vec![b' '; 4097])).is_err());
        Ok(())
    }
}
