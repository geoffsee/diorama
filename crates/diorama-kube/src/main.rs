use diorama::{StartupAction, StartupInputs};
use diorama_config::{ConfigError, DecodedConfig, HostContext};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

struct ProcessInputs;
impl StartupInputs for ProcessInputs {
    fn read_config(&mut self, path: &Path) -> Result<Option<DecodedConfig>, ConfigError> {
        diorama_config::read_file(path)
    }
    fn host(&mut self) -> io::Result<HostContext> {
        let architecture = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => other,
        };
        Ok(HostContext {
            cpu_count: host_cpu_count()?,
            architecture: architecture.into(),
            detected_container_mode: Path::new("/.dockerenv").metadata().is_ok()
                || Path::new("/run/.containerenv").metadata().is_ok()
                || std::env::var_os("container").is_some_and(|value| !value.is_empty()),
        })
    }
}
// Go runtime.NumCPU counts the Linux affinity mask, not the cgroup CPU quota.
// /proc exposes that mask without requiring unsafe sched_getaffinity FFI.
#[cfg(any(target_os = "linux", test))]
fn affinity_count(status: &str) -> Option<usize> {
    let list = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))?;
    let mut count = 0usize;
    let mut previous = None;
    for part in list.trim().split(',') {
        let (start, end) = part.split_once('-').unwrap_or((part, part));
        let start = start.parse::<usize>().ok()?;
        let end = end.parse::<usize>().ok()?;
        if start > end || previous.is_some_and(|last| start <= last) {
            return None;
        }
        count = count.checked_add(end.checked_sub(start)?.checked_add(1)?)?;
        previous = Some(end);
    }
    (count > 0).then_some(count)
}
fn host_cpu_count() -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    if let Ok(status) = std::fs::read_to_string("/proc/self/status")
        && let Some(count) = affinity_count(&status)
    {
        return Ok(count);
    }
    Ok(std::thread::available_parallelism()?.get())
}

fn run() -> io::Result<u8> {
    let args: Vec<_> = std::env::args_os()
        .skip(1)
        .map(|value| {
            value.into_string().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "command arguments must be UTF-8",
                )
            })
        })
        .collect::<Result<_, _>>()?;
    let environment: BTreeMap<_, _> = std::env::vars_os()
        .filter_map(|(key, value)| {
            key.to_str()
                .filter(|key| key.starts_with("DIORAMA_"))
                .map(str::to_owned)
                .map(|key| (key, value))
        })
        .map(|(key, value)| {
            value.into_string().map(|value| (key, value)).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "configuration environment must be UTF-8",
                )
            })
        })
        .collect::<Result<_, _>>()?;
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    match diorama::execute(
        &args,
        &environment,
        env!("CARGO_PKG_VERSION"),
        &mut ProcessInputs,
        &mut stdout,
        &mut stderr,
    )? {
        StartupAction::Exit(code) => Ok(code),
        StartupAction::Start {
            config,
            config_path,
            host,
            token_file,
            join_token,
        } => {
            drop(stdout);
            drop(stderr);
            let resolved_token = match (join_token, token_file) {
                (Some(tok), _) => Some(tok),
                (None, Some(path)) => Some(std::fs::read_to_string(path)?),
                (None, None) => None,
            };
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async move {
                match diorama::NodeRuntime::from_config_with_join(
                    *config,
                    config_path,
                    host,
                    resolved_token,
                )
                .await
                {
                    Ok(node) => node.run_to_completion().await,
                    Err(error) => {
                        // Assembly failed before a supervisor existed. Keep the
                        // original diagnostic and do not invent lifecycle events.
                        let _ = writeln!(
                            io::stderr().lock(),
                            "{{\"schema\":1,\"level\":\"error\",\"event\":\"runtime_assembly_failed\",\"code\":\"{}\"}}",
                            error.diagnostic_code()
                        );
                        Ok(1)
                    },
                }
            })
        },
    }
}
fn main() -> ExitCode {
    #[cfg(feature = "oci-cri")]
    if let Err(error) = diorama_oci::startup() {
        let _ = writeln!(
            io::stderr().lock(),
            "diorama: OCI runtime initialization: {error}"
        );
        return ExitCode::FAILURE;
    }
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "diorama: {error}");
            ExitCode::FAILURE
        },
    }
}

#[cfg(test)]
mod tests {
    use super::affinity_count;

    #[test]
    fn counts_discontiguous_affinity_without_applying_cpu_quota() {
        assert_eq!(
            affinity_count("Name:\tdiorama\nCpus_allowed_list:\t0-3,8,10-11\n"),
            Some(7)
        );
        for invalid in [
            "",
            "3-1",
            "0-3,2",
            "0,0",
            "1-2-3",
            "18446744073709551615-18446744073709551615,0",
        ] {
            assert_eq!(
                affinity_count(&format!("Cpus_allowed_list:\t{invalid}\n")),
                None
            );
        }
    }
}
