//! Owned persistent components inside the explicitly disposable Linux fixture.
use super::source_inventory;
use crate::{
    Result,
    api_json::require,
    defaults::capture::{arguments, digest},
    json,
    process::{
        Cancellation, CommandFailure, CommandRequest, CommandResult, Commands, OutputMode,
        OwnedChild, SignalGuard, SpawnRequest,
    },
};
use serde_json::{Value, json as value};
use std::{
    ffi::OsString,
    fs,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
const LOG_LIMIT: u64 = 16 * 1024 * 1024;
#[derive(Debug)]
struct Component {
    name: String,
    process: OwnedChild,
    log: PathBuf,
}
impl Component {
    fn stop(&mut self) -> Result<(i32, bool, bool)> {
        let mut forced = false;
        if self.process.poll()?.is_none() {
            self.process.signal(rustix::process::Signal::TERM)?;
            if self.process.wait(Duration::from_secs(30)).is_err() {
                forced = true;
                self.process.signal(rustix::process::Signal::KILL)?;
                self.process.wait(Duration::from_secs(5))?;
            }
        }
        let status = self.process.poll()?.ok_or("missing final status")?;
        Ok((
            crate::process::exit_code(status),
            self.process.group_absent()?,
            forced,
        ))
    }
}
#[derive(Debug)]
pub(crate) struct Runtime {
    pub report: Value,
    pub profile: String,
    children: Vec<Component>,
    commands: Commands,
    _signals: SignalGuard,
    retained: Vec<CommandFailure>,
    sequence: usize,
    state: PathBuf,
    evidence: PathBuf,
    launcher: Option<PathBuf>,
}
impl Runtime {
    pub(crate) fn new(profile: &str) -> Result<Self> {
        require(
            cfg!(target_os = "linux") && rustix::process::getuid().as_raw() == 65532,
            "runtime requires disposable Linux UID65532 fixture",
        )?;
        require(
            std::env::var("DIORAMA_DISPOSABLE_FIXTURE").as_deref() == Ok(profile),
            "explicit disposable fixture marker required",
        )?;
        fs::create_dir_all("/state/commands")?;
        let cancellation = Cancellation::default();
        let signals = SignalGuard::install(cancellation.clone())?;
        let inputs = json::parse(&crate::read_bounded(
            Path::new("/experiment/inputs.json"),
            65536,
        )?)?;
        let architecture = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            _ => return Err("unsupported fixture architecture".into()),
        };
        let source = source_inventory(Path::new("/experiment/sources"), profile)?;
        let mut runtime = Self {
            report: value!({"schema_version":2,"status":"failed","checks":[],"measurements":[],"shutdowns":[],"inputs":inputs,"architecture":architecture,"source_sha256":source}),
            profile: profile.into(),
            children: Vec::new(),
            commands: Commands {
                output: "/state/commands".into(),
                cancellation,
            },
            _signals: signals,
            retained: Vec::new(),
            sequence: 0,
            state: "/state".into(),
            evidence: "/evidence".into(),
            launcher: None,
        };
        runtime.report["kernel"] = String::from_utf8(crate::read_bounded(
            Path::new("/proc/sys/kernel/osrelease"),
            4096,
        )?)?
        .trim()
        .into();
        let pins = runtime.report["inputs"]["artifacts"][architecture]
            .as_object()
            .ok_or("artifact pins")?
            .clone();
        require(
            pins.len() == 2 && pins.contains_key("kine") && pins.contains_key("kube-apiserver"),
            "exact runtime artifact inventory",
        )?;
        for (name, pin) in pins {
            runtime.check(
                digest(&Path::new("/usr/local/bin").join(&name))? == pin["sha256"],
                &format!("runtime digest {name}"),
            )?;
        }
        Ok(runtime)
    }
    pub(crate) fn check(&mut self, condition: bool, message: &str) -> Result<()> {
        require(condition, message)?;
        self.report["checks"]
            .as_array_mut()
            .ok_or("checks")?
            .push(message.into());
        Ok(())
    }
    pub(crate) fn cancelled(&self) -> bool {
        self.commands.cancellation.requested()
    }
    pub(crate) fn uncertain(&self) -> bool {
        self.retained.iter().any(|f| !f.cleanup_complete)
    }
    pub(crate) fn command(
        &mut self,
        argv: &[OsString],
        input: &[u8],
        seconds: u64,
        required: bool,
        limit: u64,
    ) -> Result<CommandResult> {
        require(!self.uncertain(), "prior command cleanup unconfirmed")?;
        require(!self.cancelled(), "fixture cancelled")?;
        self.sequence += 1;
        let label = format!("command-{}", self.sequence);
        match self.commands.capture(CommandRequest {
            label: &label,
            argv,
            input,
            timeout: Duration::from_secs(seconds),
            required,
            byte_limit: limit,
            mode: OutputMode::Separate,
            environment: None,
            current_directory: Some(&self.state),
            launcher: self.launcher.as_deref(),
        }) {
            Ok(result) => Ok(result),
            Err(failure) => {
                let message = failure.to_string();
                self.retained.push(failure);
                Err(message.into())
            },
        }
    }
    fn openssl(&mut self, args: &[&str]) -> Result<()> {
        let mut command = arguments(&["openssl"]);
        command.extend(arguments(args));
        self.command(&command, b"", 20, true, 65536)?;
        Ok(())
    }
    pub(crate) fn credentials(&mut self) -> Result<()> {
        self.ca("ca", "boundary-test-ca")?;
        for (name, subject, extensions) in [
            (
                "server",
                "/CN=localhost",
                "subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n",
            ),
            (
                "admin",
                "/CN=boundary-admin/O=system:masters",
                "extendedKeyUsage=clientAuth\n",
            ),
            (
                "unprivileged",
                "/CN=boundary-unprivileged",
                "extendedKeyUsage=clientAuth\n",
            ),
        ] {
            self.certificate(name, subject, extensions, "ca")?;
        }
        self.openssl(&["genrsa", "-out", "service-account.key", "2048"])?;
        if self.profile == "api-json" {
            self.ca("datastore-ca", "datastore-test-ca")?;
            for (name, usage) in [
                ("datastore-server", "serverAuth"),
                ("datastore-client", "clientAuth"),
            ] {
                self.certificate(
                    name,
                    &format!("/CN={name}"),
                    &format!("subjectAltName=IP:127.0.0.1\nextendedKeyUsage={usage}\n"),
                    "datastore-ca",
                )?;
            }
        }
        Ok(())
    }
    fn ca(&mut self, name: &str, common: &str) -> Result<()> {
        self.openssl(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            &format!("/CN={common}"),
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.crt"),
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ])
    }
    fn certificate(&mut self, name: &str, subject: &str, extensions: &str, ca: &str) -> Result<()> {
        self.openssl(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            subject,
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
        ])?;
        fs::write(
            format!("/state/{name}.ext"),
            format!(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n{extensions}"
            ),
        )?;
        self.openssl(&[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            &format!("{ca}.crt"),
            "-CAkey",
            &format!("{ca}.key"),
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            &format!("{name}.ext"),
            "-out",
            &format!("{name}.crt"),
        ])
    }
    pub(crate) fn start(&mut self, name: &str, args: &[&str], cycle: &str) -> Result<()> {
        require(
            !self.cancelled() && !self.uncertain(),
            "fixture execution stopped",
        )?;
        require(
            !self.children.iter().any(|c| c.name == name),
            "component already owned",
        )?;
        let path = self.evidence.join(format!("{name}-{cycle}.log"));
        let log = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let process = OwnedChild::spawn(SpawnRequest {
            program: Path::new(name),
            argv: &arguments(args),
            environment: None,
            current_directory: Some(&self.state),
            input: fs::File::open("/dev/null")?,
            stdout: Stdio::from(log.try_clone()?),
            stderr: Stdio::from(log),
            byte_limit: LOG_LIMIT,
            uid: None,
            launcher: self.launcher.as_deref(),
        })?;
        self.children.push(Component {
            name: name.into(),
            process,
            log: path,
        });
        Ok(())
    }
    pub(crate) fn alive(&mut self) -> Result<()> {
        require(
            !self.cancelled() && !self.uncertain(),
            "fixture execution stopped",
        )?;
        for component in &mut self.children {
            require(
                component.process.poll()?.is_none(),
                "owned component exited early",
            )?;
            require(
                fs::metadata(&component.log)?.len() < LOG_LIMIT,
                "component log bound",
            )?;
        }
        Ok(())
    }
    pub(crate) fn start_kine(&mut self, cycle: &str) -> Result<()> {
        let mut args = vec![
            "--listen-address=127.0.0.1:2379",
            "--endpoint=sqlite:///state/state.db?_journal_mode=WAL&_busy_timeout=30000&_synchronous=NORMAL&_txlock=immediate&_stmt_cache_size=20&cache=shared",
            "--metrics-bind-address=0",
            "--datastore-max-idle-connections=3",
            "--datastore-max-open-connections=5",
            "--datastore-connection-max-lifetime=60s",
            "--watch-progress-notify-interval=15s",
        ];
        if self.profile == "api-json" {
            args.extend([
                "--server-cert-file=/state/datastore-server.crt",
                "--server-key-file=/state/datastore-server.key",
                "--trusted-ca-file=/state/datastore-ca.crt",
            ]);
        }
        self.start("kine", &args, cycle)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let address: SocketAddr = "127.0.0.1:2379".parse()?;
        loop {
            self.alive()?;
            if TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_ok() {
                return Ok(());
            }
            require(Instant::now() < deadline, "Kine socket startup timeout")?;
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    pub(crate) fn ready(&mut self, cycle: &str) -> Result<()> {
        let began = Instant::now();
        self.start_kine(cycle)?;
        let mut args = vec![
            "--bind-address=127.0.0.1",
            "--advertise-address=192.0.2.1",
            "--secure-port=6443",
            "--service-cluster-ip-range=10.43.0.0/16",
            "--tls-cert-file=/state/server.crt",
            "--tls-private-key-file=/state/server.key",
            "--client-ca-file=/state/ca.crt",
            "--anonymous-auth=false",
            "--authorization-mode=Node,RBAC",
            "--service-account-issuer=https://kubernetes.default.svc",
            "--service-account-signing-key-file=/state/service-account.key",
            "--service-account-key-file=/state/service-account.key",
            "--profiling=false",
            "--shutdown-delay-duration=0s",
        ];
        if self.profile == "api-json" {
            args.extend([
                "--etcd-servers=https://127.0.0.1:2379",
                "--etcd-cafile=/state/datastore-ca.crt",
                "--etcd-certfile=/state/datastore-client.crt",
                "--etcd-keyfile=/state/datastore-client.key",
            ]);
        } else {
            args.push("--etcd-servers=http://127.0.0.1:2379");
        }
        self.start("kube-apiserver", &args, cycle)?;
        self.wait_ready(cycle, began)
    }
    pub(crate) fn wait_ready(&mut self, cycle: &str, began: Instant) -> Result<()> {
        let deadline = Instant::now() + Duration::from_mins(2);
        loop {
            self.alive()?;
            if self
                .http("GET", "/readyz?verbose", None, Some("admin"), 5)
                .is_ok_and(|r| r.status == 200)
            {
                return self.measure(cycle, began.elapsed().as_secs_f64());
            }
            require(Instant::now() < deadline, "API readiness timeout")?;
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    fn measure(&mut self, cycle: &str, elapsed: f64) -> Result<()> {
        let mut components = Vec::new();
        let mut sum = 0u64;
        for component in &self.children {
            let pid = component.process.pid();
            let status = String::from_utf8(crate::read_bounded(
                &PathBuf::from(format!("/proc/{pid}/status")),
                65536,
            )?)?;
            let mut row = value!({"name":component.name,"pid":pid});
            for name in ["VmRSS", "VmHWM"] {
                let prefix = format!("{name}:");
                let words: Vec<_> = status
                    .lines()
                    .find_map(|l| l.strip_prefix(&prefix))
                    .ok_or("memory observation missing")?
                    .split_whitespace()
                    .collect();
                require(words.len() == 2 && words[1] == "kB", "memory unit")?;
                let count: u64 = words[0].parse()?;
                row[format!("{name}_kib")] = count.into();
                if name == "VmRSS" {
                    sum = sum.checked_add(count).ok_or("memory sum")?;
                }
            }
            components.push(row);
        }
        self.report["measurements"].as_array_mut().ok_or("measurements")?.push(value!({"cycle":cycle,"readiness_seconds":elapsed,"component_process_count":components.len(),"components":components,"component_rss_sum_kib":sum}));
        Ok(())
    }
    pub(crate) fn api_pid(&self) -> Result<u32> {
        self.children
            .iter()
            .find(|c| c.name == "kube-apiserver")
            .map(|c| c.process.pid())
            .ok_or_else(|| "API not owned".into())
    }
    pub(crate) fn shutdown(&mut self) -> Result<()> {
        self.children.sort_by_key(|c| c.name != "kube-apiserver");
        let mut errors = Vec::new();
        for component in &mut self.children {
            let (code, absent, forced, error) = match component.stop() {
                Ok((code, absent, forced)) => (Some(code), absent, forced, None),
                Err(error) => (None, false, true, Some(error.to_string())),
            };
            self.report["shutdowns"].as_array_mut().ok_or("shutdown records")?.push(value!({"component":component.name,"pid":component.process.pid(),"exit_code":code,"forced":forced,"owned_group_remained":!absent,"error":error}));
            if !absent || forced || error.is_some() || !matches!(code, Some(0 | -15)) {
                errors.push(component.name.clone());
            }
            if absent {
                component.process.settle(&mut errors);
            }
        }
        // Retain uncertain owners; do not signal any numeric identity after reap.
        self.children
            .retain_mut(|c| !matches!(c.process.group_absent(), Ok(true)));
        require(errors.is_empty(), "unclean owned component shutdown")
    }
    pub(crate) fn crash_kine(&mut self) -> Result<()> {
        self.alive()?;
        let index = self
            .children
            .iter()
            .position(|c| c.name == "kine")
            .ok_or("datastore owner missing")?;
        let process = &mut self.children[index].process;
        process.signal(rustix::process::Signal::KILL)?;
        let status = process.wait(Duration::from_secs(5))?;
        let code = crate::process::exit_code(status);
        let absent = process.group_absent()?;
        self.report["shutdowns"].as_array_mut().ok_or("shutdown records")?.push(value!({"component":"kine","pid":process.pid(),"exit_code":code,"injected_failure":"SIGKILL","owned_group_remained":!absent}));
        require(code == -9 && absent, "fault injected datastore settlement")?;
        let mut errors = Vec::new();
        process.settle(&mut errors);
        require(errors.is_empty(), "fault metadata cleanup")?;
        self.children.remove(index);
        self.check(true, "intentional datastore SIGKILL observed")
    }
    pub(crate) fn owners_remain(&self) -> bool {
        !self.children.is_empty() || self.uncertain()
    }
    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "Only the integration crate supplies a real Cargo executable launcher"
    )]
    pub(crate) fn testing(directory: &Path, launcher: &Path) -> Result<Self> {
        let cancellation = Cancellation::default();
        let signals = SignalGuard::install(cancellation.clone())?;
        let output = directory.join("commands");
        fs::create_dir(&output)?;
        Ok(Self {
            report: value!({"status":"failed","checks":[],"shutdowns":[],"measurements":[]}),
            profile: "test".into(),
            children: Vec::new(),
            commands: Commands {
                output,
                cancellation,
            },
            _signals: signals,
            retained: Vec::new(),
            sequence: 0,
            state: directory.into(),
            evidence: directory.into(),
            launcher: Some(launcher.into()),
        })
    }
}
