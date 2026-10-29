//! Explicit diagnostic consumer; not a node-startup executable.
use diorama::host_preflight::{AssessmentStatus, assess_node};
use diorama::{StartupAction, StartupInputs};
use diorama_config::{ConfigError, DecodedConfig, HostContext};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
struct Inputs;
impl StartupInputs for Inputs {
    fn read_config(&mut self, path: &Path) -> Result<Option<DecodedConfig>, ConfigError> {
        diorama_config::read_file(path)
    }
    fn host(&mut self) -> io::Result<HostContext> {
        Ok(HostContext {
            cpu_count: std::thread::available_parallelism()?.get(),
            architecture: match std::env::consts::ARCH {
                "aarch64" => "arm64",
                "x86_64" => "amd64",
                value => value,
            }
            .into(),
            detected_container_mode: Path::new("/.dockerenv").exists()
                || Path::new("/run/.containerenv").exists()
                || std::env::var_os("container").is_some_and(|value| !value.is_empty()),
        })
    }
}
fn run() -> io::Result<u8> {
    let args = std::env::args_os()
        .skip(1)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| io::Error::other("arguments must be UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let environment = std::env::vars_os()
        .filter(|(key, _)| key.to_str().is_some_and(|key| key.starts_with("DIORAMA_")))
        .map(|(key, value)| {
            Ok((
                key.into_string()
                    .map_err(|_| io::Error::other("configuration key must be UTF-8"))?,
                value
                    .into_string()
                    .map_err(|_| io::Error::other("configuration value must be UTF-8"))?,
            ))
        })
        .collect::<io::Result<BTreeMap<_, _>>>()?;
    let action = diorama::execute(
        &args,
        &environment,
        env!("CARGO_PKG_VERSION"),
        &mut Inputs,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )?;
    let StartupAction::Start { config, .. } = action else {
        let StartupAction::Exit(code) = action else {
            return Ok(1);
        };
        return Ok(code);
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(async {
        use tokio::signal::unix::{SignalKind, signal};
        // Install before any assessment effect; keep both listeners alive through owned cleanup.
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        Ok::<_, io::Error>(
            assess_node(&config, async {
                tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
            })
            .await,
        )
    })?;
    if report.status == AssessmentStatus::CleanupIncomplete {
        return Ok(2);
    }
    writeln!(
        io::stdout().lock(),
        "Node assessment: {:?}; runtime: {:?}; container preparation: {:?}",
        report.status,
        report.runtime,
        report.container_preparation
    )?;
    if let Some(version) = report.version {
        writeln!(
            io::stdout().lock(),
            "Module family: {:?}; probe: {:?}",
            version.family,
            version.failure
        )?;
    }
    Ok(u8::from(report.status != AssessmentStatus::Observed))
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("assessment failed before a result was available: {error}");
            ExitCode::FAILURE
        },
    }
}
