//! Owned Alpine guest boundary shared by preparation and node qualification.
use super::{
    BTreeMap, OsString, Path, PathBuf, Result, Value, digest, equal, json, read, require, text,
};
use crate::parity::{
    lifecycle,
    process::{Cancellation, CommandFailure, CommandResult, Commands, OwnedChild, SpawnRequest},
    vm::{Console, executable, qmp_powerdown},
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::time::{Duration, Instant};
// Both reviewed edk2-aarch64-code.fd and edk2-arm-vars.fd images are exactly 64 MiB.
const FIRMWARE_BYTES: u64 = 64 * 1024 * 1024;
fn firmware_bytes(path: &Path, expected_sha256: &str) -> Result<Vec<u8>> {
    let bytes = read(path, FIRMWARE_BYTES)?;
    require(
        bytes.len() as u64 == FIRMWARE_BYTES,
        "exact reviewed firmware size",
    )?;
    require(
        diorama_dev::sha256(&bytes) == expected_sha256,
        "firmware digest mismatch",
    )?;
    Ok(bytes)
}
pub(crate) struct GuestSpec<'a> {
    pub output: &'a Path,
    pub image_cache: &'a Path,
    pub inputs: Value,
    pub source_sha256: Value,
    pub revision: String,
    pub adapter: &'a str,
    pub injection: Option<&'a str>,
}
pub(crate) struct Guest {
    pub report: Value,
    commands: Commands,
    cleanup: Commands,
    owner: Option<OwnedChild>,
    console: Option<Console>,
    private: Option<PathBuf>,
    ssh: Vec<OsString>,
    scp: Vec<OsString>,
    secrets: Vec<Vec<u8>>,
}
impl Guest {
    /// The constrained observer includes bounded failure diagnostics after snapshots.
    /// Keep this larger budget exclusive to that exact command and adapter.
    pub(crate) fn remote_constrained(&self, input: &[u8]) -> Result<CommandResult> {
        super::command_evidence::constrained_policy(
            &self.report,
            "constrained-cases",
            "DIORAMA_RUN_PREPARATION=1 sh -s",
        )?;
        let label = "constrained-cases";
        write_new(&self.commands.output.join(format!("{label}.stdin")), input)?;
        let mut argv = self.ssh.clone();
        argv.push("DIORAMA_RUN_PREPARATION=1 sh -s".into());
        let result = self.commands.run(
            label,
            &argv,
            Duration::from_mins(10),
            input,
            true,
            super::command_evidence::CONSTRAINED_LIMIT,
        );
        let path = self.commands.output.join(format!("{label}.command.json"));
        match result {
            Ok(mut result) => {
                result.receipt["byte_limit"] = json!(super::command_evidence::CONSTRAINED_LIMIT);
                crate::parity::write_json(&path, &result.receipt, false)?;
                Ok(result)
            },
            Err(mut error) => {
                if let Some(failure) =
                    error.downcast_mut::<crate::parity::process::CommandFailure>()
                {
                    failure.receipt["byte_limit"] =
                        json!(super::command_evidence::CONSTRAINED_LIMIT);
                    if let Err(publication) =
                        crate::parity::write_json(&path, &failure.receipt, false)
                    {
                        eprintln!("constrained bound receipt publication: {publication}");
                    }
                }
                Err(error)
            },
        }
    }
    pub(crate) fn private(&self) -> Result<&Path> {
        self.private
            .as_deref()
            .ok_or_else(|| "guest private owner missing".into())
    }
    pub(crate) fn remote(
        &self,
        label: &str,
        command: &str,
        seconds: u64,
        input: &[u8],
        required: bool,
    ) -> Result<CommandResult> {
        if label == "constrained-cases" {
            super::command_evidence::constrained_policy(&self.report, label, command)?;
            require(
                seconds == 600 && required,
                "fixed constrained command policy",
            )?;
            return self.remote_constrained(input);
        }
        write_new(&self.commands.output.join(format!("{label}.stdin")), input)?;
        let mut argv = self.ssh.clone();
        argv.push(command.into());
        self.commands.run(
            label,
            &argv,
            Duration::from_secs(seconds),
            input,
            required,
            256 * 1024,
        )
    }
    pub(crate) fn upload_directory(
        &self,
        label: &str,
        local: &Path,
        destination: &str,
    ) -> Result<()> {
        require(
            destination.starts_with('/') && !destination.contains(['\n', '\0']),
            "absolute guest destination",
        )?;
        let mut argv = self.scp.clone();
        argv.push("-r".into());
        argv.push(local.into());
        argv.push(format!("root@127.0.0.1:{destination}").into());
        self.commands
            .run(label, &argv, Duration::from_mins(1), b"", true, 256 * 1024)?;
        Ok(())
    }
    pub(crate) fn reboot(&mut self) -> Result<()> {
        let previous = self
            .remote(
                "before-reboot-id",
                "cat /proc/sys/kernel/random/boot_id",
                30,
                b"",
                true,
            )?
            .stdout;
        self.remote("guest-reboot", "reboot", 30, b"", false)?;
        let started = Instant::now();
        let mut attempt = 0usize;
        loop {
            require(
                started.elapsed() < Duration::from_mins(3),
                "reboot deadline",
            )?;
            require(
                self.owner.as_mut().ok_or("guest owner")?.poll()?.is_none(),
                "guest exited during reboot",
            )?;
            attempt += 1;
            let current = self.remote(
                &format!("reboot-readiness-{attempt:03}"),
                "cat /proc/sys/kernel/random/boot_id",
                8,
                b"",
                false,
            )?;
            if current.code == 0
                && !current.stdout.trim().is_empty()
                && current.stdout.trim() != previous.trim()
            {
                self.report["reboot_readiness_label"] =
                    json!(format!("reboot-readiness-{attempt:03}"));
                write_new(
                    &self.commands.output.join("reboot-readiness.stdout"),
                    &current.stdout_bytes,
                )?;
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        self.cloud("reboot-cloud-init", "reboot_cloud_init")
    }
    fn cloud(&mut self, label: &str, key: &str) -> Result<()> {
        let result = self.remote(
            label,
            "cloud-init status --wait --long --format json",
            60,
            b"",
            false,
        )?;
        let value = diorama_dev::json::parse(&result.stdout_bytes)?;
        super::alpine::cloud(i64::from(result.code), &value)?;
        self.report[key] = value;
        self.report[format!("{key}_exit")] = json!(result.code);
        Ok(())
    }
    #[allow(
        clippy::too_many_lines,
        reason = "Sequential VM preparation tied to one retained resource owner"
    )]
    fn boot(&mut self, spec: &GuestSpec<'_>) -> Result<()> {
        require(
            cfg!(all(target_os = "macos", target_arch = "aarch64")),
            "Alpine VM requires Darwin arm64/HVF",
        )?;
        require(
            !self.commands.cancellation.requested(),
            "cancelled before VM preparation",
        )?;
        let mut tools = serde_json::Map::new();
        for name in [
            "qemu-system-aarch64",
            "qemu-img",
            "ssh",
            "ssh-keygen",
            "scp",
        ] {
            let path = executable(name)?;
            let hash = digest(&path)?;
            equal(
                &json!(hash),
                &spec.inputs["host_tools"][name],
                "pinned host executable",
            )?;
            tools.insert(name.into(), json!({"path":path,"sha256":hash}));
        }
        self.report["tools"] = Value::Object(tools);
        let firmware = Path::new("/opt/homebrew/share/qemu/edk2-aarch64-code.fd");
        let variables = Path::new("/opt/homebrew/share/qemu/edk2-arm-vars.fd");
        self.report["firmware"] =
            json!({"code_sha256":digest(firmware)?,"vars_template_sha256":digest(variables)?});
        equal(
            &self.report["firmware"],
            &spec.inputs["firmware"],
            "firmware pins",
        )?;
        firmware_bytes(
            firmware,
            spec.inputs["firmware"]["code_sha256"]
                .as_str()
                .ok_or("firmware code pin")?,
        )?;
        let variables_bytes = firmware_bytes(
            variables,
            spec.inputs["firmware"]["vars_template_sha256"]
                .as_str()
                .ok_or("firmware vars pin")?,
        )?;
        self.report["qemu_version"] = json!(
            self.commands
                .run(
                    "qemu-version",
                    &crate::parity::args(&["qemu-system-aarch64", "--version"]),
                    Duration::from_secs(30),
                    b"",
                    true,
                    256 * 1024
                )?
                .stdout
        );
        let image = download(&self.commands, spec.image_cache, &spec.inputs["image"])?;
        self.report["base_image_path"] = json!(image);
        let private = tempfile::Builder::new()
            .prefix("diorama-vm-")
            .tempdir_in("/tmp")?
            .keep();
        self.private = Some(private.clone());
        self.report["owned_temporary_directory"] = json!(private);
        write_new(&private.join("vars.fd"), &variables_bytes)?;
        self.commands.run(
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
                private.join("disk.qcow2").into(),
                "8G".into(),
            ],
            Duration::from_secs(30),
            b"",
            true,
            256 * 1024,
        )?;
        for name in ["client", "host"] {
            self.commands.run(
                &format!("key-{name}"),
                &[
                    "ssh-keygen".into(),
                    "-q".into(),
                    "-t".into(),
                    "ed25519".into(),
                    "-N".into(),
                    "".into(),
                    "-C".into(),
                    format!("diorama-alpine-fixture-{name}").into(),
                    "-f".into(),
                    private.join(name).into(),
                ],
                Duration::from_secs(30),
                b"",
                true,
                256 * 1024,
            )?;
        }
        let host_private = text(&private.join("host"))?;
        let host_public = text(&private.join("host.pub"))?;
        let client_public = text(&private.join("client.pub"))?;
        let mut random = [0u8; 48];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let mut password = String::new();
        for byte in random {
            use std::fmt::Write as _;
            write!(&mut password, "{byte:02x}")?;
        }
        self.secrets = vec![
            password.as_bytes().to_vec(),
            host_private.as_bytes().to_vec(),
            read(&private.join("client"), 4096)?,
        ];
        self.report["guest_host_public_key"] = json!(host_public.trim());
        let mut indented = String::new();
        for line in host_private.lines() {
            use std::fmt::Write as _;
            writeln!(&mut indented, "    {line}")?;
        }
        let user = format!(
            "#cloud-config\ndisable_root: false\nssh_pwauth: false\nusers:\n  - name: root\n    lock_passwd: false\n    plain_text_passwd: {password}\n    ssh_authorized_keys:\n      - {}\nssh_keys:\n  ed25519_private: |\n{indented}  ed25519_public: {}\n",
            client_public.trim(),
            host_public.trim()
        );
        let metadata = format!(
            "instance-id: diorama-{}\nlocal-hostname: diorama-parity\n",
            diorama_dev::sha256(private.as_os_str().as_encoded_bytes())
        );
        write_new(
            &private.join("seed.iso"),
            &crate::parity::seed::image(user.as_bytes(), metadata.as_bytes())?,
        )?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        write_new(
            &private.join("known_hosts"),
            format!("[127.0.0.1]:{port} {}\n", host_public.trim()).as_bytes(),
        )?;
        let forward = format!("127.0.0.1:{port}");
        self.report["ssh_forward"] = json!(forward);
        let mut ssh_options = crate::parity::args(&["-F", "/dev/null", "-i"]);
        ssh_options.push(private.join("client").into());
        for option in [
            "BatchMode=yes".into(),
            "IdentitiesOnly=yes".into(),
            "IdentityAgent=none".into(),
            "GlobalKnownHostsFile=/dev/null".into(),
            "StrictHostKeyChecking=yes".into(),
            format!(
                "UserKnownHostsFile={}",
                private.join("known_hosts").display()
            ),
            "ConnectTimeout=3".into(),
            "ConnectionAttempts=1".into(),
            "ServerAliveInterval=5".into(),
            "ServerAliveCountMax=2".into(),
        ] {
            ssh_options.push("-o".into());
            ssh_options.push(option.into());
        }
        self.ssh = vec!["ssh".into()];
        self.ssh.extend(ssh_options.clone());
        self.ssh.extend(crate::parity::args(&[
            "-p",
            &port.to_string(),
            "root@127.0.0.1",
        ]));
        self.scp = vec!["scp".into()];
        self.scp.extend(ssh_options);
        self.scp
            .extend(crate::parity::args(&["-P", &port.to_string()]));
        let qemu = super::alpine::qemu_argv(private.to_str().ok_or("private UTF-8")?, &forward);
        self.report["qemu_argv"] = json!(qemu);
        require(
            !self.commands.cancellation.requested(),
            "cancelled before owned VM spawn",
        )?;
        let (reader, writer) = UnixStream::pair()?;
        let stderr = writer.try_clone()?;
        self.owner = Some(OwnedChild::spawn(SpawnRequest {
            program: Path::new(&qemu[0]),
            argv: &qemu[1..].iter().map(OsString::from).collect::<Vec<_>>(),
            environment: None,
            current_directory: None,
            input: File::open("/dev/null")?,
            stdout: Stdio::from(OwnedFd::from(writer)),
            stderr: Stdio::from(OwnedFd::from(stderr)),
            byte_limit: 16 * 1024 * 1024 * 1024,
            uid: None,
            launcher: None,
        })?);
        self.report["owned_pid"] = json!(self.owner.as_ref().ok_or("owner")?.pid());
        self.console = Some(Console::start(reader, &spec.output.join("serial.log"))?);
        let began = Instant::now();
        let mut attempt = 0usize;
        loop {
            require(
                began.elapsed() < Duration::from_mins(3),
                "SSH readiness deadline",
            )?;
            require(
                self.owner.as_mut().ok_or("owner")?.poll()?.is_none(),
                "QEMU exited during boot",
            )?;
            attempt += 1;
            if self
                .remote(
                    &format!("ssh-readiness-{attempt:03}"),
                    "true",
                    8,
                    b"",
                    false,
                )?
                .code
                == 0
            {
                self.report["ssh_readiness_label"] = json!(format!("ssh-readiness-{attempt:03}"));
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        self.report["ssh_readiness_seconds"] = json!(began.elapsed().as_secs_f64());
        self.cloud("cloud-init", "cloud_init")?;
        self.report["environment"] = json!(
            self.remote(
                "environment",
                "uname -a; id; cat /etc/os-release; cat /proc/self/cgroup",
                30,
                b"",
                true
            )?
            .stdout
        );
        self.remote("privileged-probe","mkdir -p /mnt/diorama-probe && mount -t tmpfs -o size=1m tmpfs /mnt/diorama-probe && umount /mnt/diorama-probe && rmdir /mnt/diorama-probe",30,b"",true)?;
        self.report["privileged_mount_probe"] = json!("passed");
        Ok(())
    }
}
fn write_new(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(raw)?;
    Ok(())
}
fn download(commands: &Commands, cache: &Path, pin: &Value) -> Result<PathBuf> {
    require(!cache.is_symlink(), "image cache symlink")?;
    fs::create_dir_all(cache)?;
    let url = pin["url"].as_str().ok_or("image URL")?;
    require(url.starts_with("https://"), "HTTPS image required")?;
    let name = url.rsplit('/').next().ok_or("image basename")?;
    require(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
        "safe image basename",
    )?;
    let image = cache.join(name);
    require(!image.is_symlink(), "image cache entry symlink")?;
    if !image.exists() {
        let partial = tempfile::NamedTempFile::new_in(cache)?;
        let result = commands.run(
            "image-download",
            &[
                "curl".into(),
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
                url.into(),
            ],
            Duration::from_secs(610),
            b"",
            true,
            256 * 1024,
        );
        if let Err(error) = result {
            if error
                .downcast_ref::<CommandFailure>()
                .is_some_and(|e| !e.cleanup_complete)
                && let Err(retain_error) = partial.keep()
            {
                // An uncertain writer still owns this path. Keep its file handle and
                // cleanup guard alive even when persisting the temporary name fails.
                std::mem::forget(retain_error.file);
            }
            return Err(error);
        }
        equal(
            &json!(crate::parity::digest(partial.path(), true)?),
            &pin["sha512"],
            "download image digest",
        )?;
        partial.persist_noclobber(&image)?;
    }
    equal(
        &json!(crate::parity::digest(&image, true)?),
        &pin["sha512"],
        "cached image digest",
    )?;
    equal(
        &json!(fs::metadata(&image)?.len()),
        &pin["bytes"],
        "image size",
    )?;
    Ok(image.canonicalize()?)
}
#[derive(Debug)]
struct Retained {
    commands: Vec<CommandFailure>,
    owner: Option<OwnedChild>,
    console: Option<Console>,
}
impl std::fmt::Display for Retained {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "guest ownership uncertain: {} command owners, QEMU {}, console {}",
            self.commands.len(),
            self.owner.is_some(),
            self.console.is_some()
        )
    }
}
impl std::error::Error for Retained {}
fn error(error: diorama_dev::Error, errors: &mut Vec<String>, retained: &mut Vec<CommandFailure>) {
    errors.push(error.to_string());
    if let Ok(failure) = error.downcast::<CommandFailure>()
        && !failure.cleanup_complete
    {
        retained.push(*failure);
    }
}
#[allow(
    clippy::too_many_lines,
    reason = "Keep all VM and command owners in scope through settlement"
)]
pub(crate) fn capture(
    spec: &GuestSpec<'_>,
    cancellation: Cancellation,
    run: impl FnOnce(&mut Guest) -> Result<()>,
) -> Result<Value> {
    fs::create_dir_all(spec.output.parent().ok_or("output parent")?)?;
    fs::create_dir(spec.output)?;
    fs::set_permissions(spec.output, fs::Permissions::from_mode(0o700))?;
    let mut guest = Guest {
        report: json!({"schema_version":2,"status":"failed","errors":[],"adapter":spec.adapter,"inputs":spec.inputs,"source_sha256":spec.source_sha256,"revision":spec.revision,"working_tree_snapshot":true,"explicit_privilege_opt_in":true,"serial_log_truncated":false}),
        commands: Commands {
            output: spec.output.into(),
            cancellation,
        },
        cleanup: Commands {
            output: spec.output.into(),
            cancellation: Cancellation::default(),
        },
        owner: None,
        console: None,
        private: None,
        ssh: vec![],
        scp: vec![],
        secrets: vec![],
    };
    let mut errors = vec![];
    let mut retained = vec![];
    let operation = (|| -> Result<()> {
        guest.boot(spec)?;
        require(spec.injection != Some("setup"), "intentional setup failure")?;
        run(&mut guest)?;
        require(spec.injection != Some("test"), "intentional test failure")?;
        guest.report["status"] = json!("passed");
        Ok(())
    })();
    if let Err(failure) = operation {
        error(failure, &mut errors, &mut retained);
    }
    let mut absent = guest.owner.is_none() && retained.is_empty();
    if let Some(owner) = guest.owner.as_mut() {
        let running = match owner.poll() {
            Ok(status) => status.is_none(),
            Err(failure) => {
                errors.push(failure.to_string());
                false
            },
        };
        if retained.is_empty() && running {
            let mut argv = guest.ssh.clone();
            argv.push("poweroff".into());
            let result = guest
                .cleanup
                .run(
                    "guest-poweroff",
                    &argv,
                    Duration::from_secs(10),
                    b"",
                    false,
                    256 * 1024,
                )
                .and_then(|_| {
                    owner.wait(Duration::from_secs(30))?;
                    Ok(())
                });
            match result {
                Ok(()) => guest.report["shutdown"] = json!("guest-poweroff"),
                Err(failure) => error(failure, &mut errors, &mut retained),
            }
        }
        let private = guest.private.as_ref().ok_or("guest private owner")?;
        let settled = lifecycle::settle_vm(
            owner,
            || {
                require(
                    retained.is_empty(),
                    "diagnostics suppressed while helper cleanup uncertain",
                )?;
                let mut argv = guest.ssh.clone();
                argv.push("rc-status -a; ps".into());
                match guest.cleanup.run(
                    "guest-diagnostics",
                    &argv,
                    Duration::from_secs(10),
                    b"",
                    false,
                    256 * 1024,
                ) {
                    Ok(_) => Ok(()),
                    Err(failure) => {
                        if let Ok(failure) = failure.downcast::<CommandFailure>()
                            && !failure.cleanup_complete
                        {
                            retained.push(*failure);
                        }
                        Err("guest diagnostics failed".into())
                    },
                }
            },
            || qmp_powerdown(&private.join("qmp.sock")),
            &mut errors,
        );
        for (key, value) in settled.as_object().ok_or("settlement object")? {
            guest.report[key] = value.clone();
        }
        absent = settled["owned_process_group_absent"] == true && retained.is_empty();
        owner.settle(&mut errors);
    }
    if let Some(reader) = guest.console.as_mut() {
        match reader.finish() {
            Ok(truncated) => guest.report["serial_log_truncated"] = json!(truncated),
            Err(failure) => {
                errors.push(failure.to_string());
                absent = false;
            },
        }
    }
    if let Some(private) = &guest.private {
        guest.report["owned_temporary_directory_removed"] =
            json!(lifecycle::remove_private(private, absent, &mut errors));
    }
    if guest.commands.cancellation.requested() {
        errors.push("cancelled through guest settlement".into());
    }
    if let Err(failure) = scrub_files(spec.output, &guest.secrets, &mut errors) {
        errors.push(format!("credential audit: {failure}"));
    }
    if guest.report["serial_log_truncated"] == true {
        errors.push("serial output reached its limit".into());
    }
    if !errors.is_empty() {
        guest.report["status"] = json!("failed");
    }
    guest.report["errors"] = json!(errors);
    guest.report["retained_commands"] =
        json!(retained.iter().map(|r| &r.receipt).collect::<Vec<_>>());
    match evidence_inventory(spec.output) {
        Ok(inventory) => guest.report["evidence_sha256"] = inventory,
        Err(failure) => {
            guest.report["status"] = json!("failed");
            guest.report["errors"]
                .as_array_mut()
                .ok_or("error array")?
                .push(json!(format!("evidence inventory: {failure}")));
        },
    }
    scrub_value(&mut guest.report, &guest.secrets);
    let publication = publish_cancellable(
        &spec.output.join("result.json"),
        &mut guest.report,
        &guest.commands.cancellation,
        true,
    );
    if !absent {
        return Err(Box::new(Retained {
            commands: retained,
            owner: guest.owner,
            console: guest.console,
        }));
    }
    publication?;
    Ok(guest.report)
}
pub(crate) fn publish_cancellable(
    path: &Path,
    report: &mut Value,
    cancellation: &Cancellation,
    create: bool,
) -> Result<()> {
    publish_with_checkpoint(path, report, cancellation, create, || {})
}
fn publish_with_checkpoint(
    path: &Path,
    report: &mut Value,
    cancellation: &Cancellation,
    create: bool,
    checkpoint: impl FnOnce(),
) -> Result<()> {
    mark_cancellation(report, cancellation)?;
    crate::parity::write_json(path, report, create)?;
    checkpoint();
    if cancellation.requested() && report["cancelled"] != true {
        mark_cancellation(report, cancellation)?;
        crate::parity::write_json(path, report, false)?;
    }
    Ok(())
}
fn mark_cancellation(report: &mut Value, cancellation: &Cancellation) -> Result<()> {
    report["cancelled"] = json!(cancellation.requested());
    if cancellation.requested() {
        report["status"] = json!("failed");
        report["errors"]
            .as_array_mut()
            .ok_or("report errors")?
            .push(json!("cancelled through final publication"));
    }
    Ok(())
}
fn secret(raw: &[u8], secrets: &[Vec<u8>]) -> bool {
    raw.windows(b"BEGIN OPENSSH PRIVATE KEY".len())
        .any(|w| w == b"BEGIN OPENSSH PRIVATE KEY")
        || secrets
            .iter()
            .filter(|s| !s.is_empty())
            .any(|s| raw.windows(s.len()).any(|w| w == s))
}
fn scrub_value(value: &mut Value, secrets: &[Vec<u8>]) {
    match value {
        Value::String(text) if secret(text.as_bytes(), secrets) => {
            *text = "[credential-bearing value suppressed]".into();
        },
        Value::Array(values) => {
            for value in values {
                scrub_value(value, secrets);
            }
        },
        Value::Object(values) => {
            for value in values.values_mut() {
                scrub_value(value, secrets);
            }
        },
        _ => {},
    }
}
fn scrub_files(output: &Path, secrets: &[Vec<u8>], errors: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(output)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        require(!kind.is_symlink(), "evidence symlink")?;
        if kind.is_dir() {
            scrub_files(&entry.path(), secrets, errors)?;
        } else if kind.is_file() {
            let raw = read(&entry.path(), 32 * 1024 * 1024)?;
            if secret(&raw, secrets) {
                crate::parity::write_json(
                    &entry.path(),
                    &json!("credential-bearing diagnostic suppressed"),
                    false,
                )?;
                errors.push(format!(
                    "credential-bearing diagnostic suppressed: {}",
                    entry.file_name().to_string_lossy()
                ));
            }
        }
    }
    Ok(())
}
pub(crate) fn evidence_inventory(output: &Path) -> Result<Value> {
    fn walk(
        root: &Path,
        path: &Path,
        inventory: &mut BTreeMap<String, String>,
        total: &mut u64,
    ) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            require(!kind.is_symlink(), "evidence symlink")?;
            if kind.is_dir() {
                walk(root, &entry.path(), inventory, total)?;
            } else {
                require(kind.is_file(), "regular evidence file required")?;
                let name = entry
                    .path()
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .into_owned();
                if name == "result.json" {
                    continue;
                }
                require(inventory.len() < 4096, "evidence entry bound")?;
                let bytes = read(&entry.path(), 32 * 1024 * 1024)?;
                *total += bytes.len() as u64;
                require(*total <= 256 * 1024 * 1024, "total evidence byte bound")?;
                inventory.insert(name, diorama_dev::sha256(&bytes));
            }
        }
        Ok(())
    }
    let mut inventory = BTreeMap::new();
    walk(output, output, &mut inventory, &mut 0)?;
    Ok(serde_json::to_value(inventory)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_firmware_accepts_exact_64_mib_and_rejects_size_hash_and_symlink_changes() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("vars.fd");
        let mut file = File::create(&path)?;
        file.write_all(b"reviewed firmware fixture")?;
        file.set_len(FIRMWARE_BYTES)?;
        let expected = digest(&path)?;
        let bytes = firmware_bytes(&path, &expected)?;
        assert_eq!(bytes.len() as u64, FIRMWARE_BYTES);
        assert!(bytes.starts_with(b"reviewed firmware fixture"));
        drop(bytes);
        assert!(firmware_bytes(&path, &"0".repeat(64)).is_err());
        let link = directory.path().join("alias.fd");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(firmware_bytes(&link, &expected).is_err());
        file.set_len(FIRMWARE_BYTES + 1)?;
        assert!(firmware_bytes(&path, &expected).is_err());
        file.set_len(FIRMWARE_BYTES - 1)?;
        assert!(firmware_bytes(&path, &expected).is_err());
        file.set_len(8 * 1024 * 1024)?;
        assert!(firmware_bytes(&path, &digest(&path)?).is_err());
        Ok(())
    }
    #[test]
    fn credential_suppression_recurses_and_preserves_failure() -> Result<()> {
        let dir = tempfile::tempdir()?;
        fs::create_dir(dir.path().join("nested"))?;
        fs::write(
            dir.path().join("nested/log"),
            b"prefix secret-password suffix",
        )?;
        let secrets = vec![b"secret-password".to_vec()];
        let mut errors = vec![];
        scrub_files(dir.path(), &secrets, &mut errors)?;
        assert_eq!(errors.len(), 1);
        assert!(!secret(
            &read(&dir.path().join("nested/log"), 4096)?,
            &secrets
        ));
        let mut report = json!({"nested":[{"error":"secret-password"}]});
        scrub_value(&mut report, &secrets);
        assert!(!report.to_string().contains("secret-password"));
        Ok(())
    }
    #[test]
    fn evidence_manifest_rejects_aliases_and_detects_nested_mutation() -> Result<()> {
        let dir = tempfile::tempdir()?;
        fs::create_dir(dir.path().join("nested"))?;
        fs::write(dir.path().join("nested/a"), b"before")?;
        let before = evidence_inventory(dir.path())?;
        fs::write(dir.path().join("nested/a"), b"after")?;
        assert_ne!(before, evidence_inventory(dir.path())?);
        std::os::unix::fs::symlink(dir.path().join("nested/a"), dir.path().join("alias"))?;
        assert!(evidence_inventory(dir.path()).is_err());
        Ok(())
    }
}
#[cfg(test)]
mod publication_tests {
    use super::*;
    #[test]
    fn cancellation_during_scrubbing_or_publication_cannot_leave_success() -> Result<()> {
        for during_write in [false, true] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("result.json");
            let mut report = json!({"status":"passed","errors":[]});
            let cancellation = Cancellation::default();
            if !during_write {
                cancellation.request();
            }
            publish_with_checkpoint(&path, &mut report, &cancellation, true, || {
                if during_write {
                    cancellation.request();
                }
            })?;
            let saved = super::super::load(&path)?;
            require(
                saved["status"] == "failed"
                    && saved["cancelled"] == true
                    && !saved["errors"].as_array().ok_or("errors")?.is_empty(),
                "late cancellation persisted",
            )?;
        }
        Ok(())
    }
}
