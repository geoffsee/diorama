use diorama_platform::preflight::PortAvailability;
use diorama_platform::preflight_probe::{SupplementalFacts, collect_supplemental, probe_ports};
use diorama_platform::{
    DiscoveryRequest, HostEvidence, Observation, PlatformError, ProbeLimits, discover,
};
use std::collections::BTreeMap;
use std::io::{self, Write};
struct Host;
impl dioramactl::CheckInputs for Host {
    fn discover(&mut self) -> Result<HostEvidence, PlatformError> {
        discover(&DiscoveryRequest::default())
    }
    fn supplemental(&mut self) -> Result<SupplementalFacts, PlatformError> {
        collect_supplemental(ProbeLimits::default())
    }
    fn ports(&mut self, pprof: bool) -> Result<[Observation<PortAvailability>; 4], PlatformError> {
        probe_ports(pprof)
    }
    fn download_file(
        &mut self,
        url: &str,
        dest: &std::path::Path,
        proxy: Option<&str>,
        temp_dir: Option<&std::path::Path>,
    ) -> io::Result<()> {
        dioramactl::download::stage_download(dest, temp_dir, |staged| {
            let status = dioramactl::download::run_curl_download(url, staged, proxy)?;
            if !status.success() {
                return Err(io::Error::other(format!(
                    "curl failed with status: {status}"
                )));
            }
            Ok(())
        })
    }
    fn copy_self(&mut self, dest: &std::path::Path) -> io::Result<()> {
        let current_exe = std::env::current_exe()?;
        let mut source = std::fs::File::open(current_exe)?;
        dioramactl::download::stage_installer(dest, |installer| {
            io::copy(&mut source, installer)?;
            Ok(())
        })
    }
    fn read_parent_environ(&mut self) -> io::Result<Vec<u8>> {
        let status = std::fs::read_to_string("/proc/self/status")?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("PPid:") {
                let ppid: u32 = rest
                    .trim()
                    .parse()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                return std::fs::read(format!("/proc/{ppid}/environ"));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "PPid not found in /proc/self/status",
        ))
    }
}
fn main() -> std::process::ExitCode {
    let Ok(args): Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect()
    else {
        let _ = writeln!(io::stderr(), "error: command arguments must be UTF-8");
        return std::process::ExitCode::FAILURE;
    };
    let mut environment = BTreeMap::new();
    for (key, value) in std::env::vars_os() {
        let Ok(key) = key.into_string() else { continue };
        if !(key.starts_with("DIORAMA_")
            || matches!(
                key.as_str(),
                "SUDO_USER" | "TEMP_DIR" | "HTTP_PROXY" | "HTTPS_PROXY"
            ))
        {
            continue;
        }
        let Ok(value) = value.into_string() else {
            let _ = writeln!(
                io::stderr(),
                "error: management environment inputs must be UTF-8"
            );
            return std::process::ExitCode::FAILURE;
        };
        environment.insert(key, value);
    }
    let parsed = dioramactl::parse_command(&args, &environment);
    if let Ok(dioramactl::Command::Check(options)) = parsed
        && options.install_prerequisites
    {
        return preparation(options);
    }
    if let Ok(code) = dioramactl::execute(
        &args,
        &environment,
        env!("CARGO_PKG_VERSION"),
        &mut Host,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    ) {
        code.into()
    } else {
        let _ = writeln!(io::stderr(), "error: management output failed");
        std::process::ExitCode::FAILURE
    }
}

fn preparation(options: dioramactl::CheckOptions) -> std::process::ExitCode {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        let _ = writeln!(
            io::stderr(),
            "error: prerequisite runtime could not be initialized"
        );
        return std::process::ExitCode::FAILURE;
    };
    let cancellation = dioramactl::preparation::Cancellation::default();
    let mut executor = dioramactl::preparation::AlpinePreparation;
    let mut host = Host;
    let mut stderr = io::stderr().lock();
    let workflow = dioramactl::check_workflow::execute_check_with_preparation(
        options,
        &mut host,
        &mut executor,
        &cancellation,
        &mut stderr,
    );
    match runtime.block_on(dioramactl::preparation::with_signals(
        &cancellation,
        workflow,
    )) {
        Ok(Ok(code)) => code.into(),
        Ok(Err(_)) => {
            let _ = writeln!(stderr, "error: management output failed");
            std::process::ExitCode::FAILURE
        },
        Err(_) => {
            let _ = writeln!(
                stderr,
                "error: prerequisite signal listeners could not be installed; no checks or preparation were started"
            );
            std::process::ExitCode::FAILURE
        },
    }
}
