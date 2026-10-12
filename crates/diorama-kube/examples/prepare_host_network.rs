//! Explicit shared-network preparation consumer; not a node-startup executable.
use diorama::host_network::{NetworkStatus, prepare_node_network};
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
        .filter(|(key, _)| key.to_str().is_some_and(|key| key.starts_with("KUBESOLO_")))
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
            prepare_node_network(&config, async {
                tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
            })
            .await,
        )
    })?;
    if report.status == NetworkStatus::CleanupIncomplete {
        return Ok(2);
    }
    let modules = report
        .modules
        .iter()
        .map(|step| {
            serde_json::json!({
                "name": step.module.name(), "outcome": format!("{:?}", step.command.outcome),
                "spawned": step.command.cleanup.spawned,
                "joined": step.command.cleanup.thread_joined,
                "reaped": step.command.cleanup.leader_reaped,
                "ownership_lost": step.command.cleanup.ownership_lost,
                "exit": step.command.cleanup.exit.map(|exit| exit.code),
                "after": step.after.as_ref().map(|after| serde_json::json!({
                    "loaded": format!("{:?}", after.loaded),
                    "builtin_index": format!("{:?}", after.builtin_index),
                    "available_index": format!("{:?}", after.available_index),
                })),
            })
        })
        .collect::<Vec<_>>();
    let ipv6 = report
        .ipv6
        .iter()
        .map(|step| {
            serde_json::json!({
                "path": step.control.path(), "outcome": format!("{:?}", step.outcome),
            })
        })
        .collect::<Vec<_>>();
    let result = serde_json::json!({
        "schema": 1, "status": format!("{:?}", report.status),
        "assessment": format!("{:?}", report.assessment.status),
        "runtime": format!("{:?}", report.assessment.runtime),
        "family": report.assessment.constrained.as_ref().map(|facts| format!("{:?}", facts.module_family)),
        "shared_effects_possible": report.shared_effects_possible,
        "modules": modules, "ipv6": ipv6,
    });
    writeln!(io::stdout().lock(), "{result}")?;
    Ok(u8::from(report.status != NetworkStatus::Completed))
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("network preparation failed before a result was available: {error}");
            ExitCode::FAILURE
        },
    }
}
