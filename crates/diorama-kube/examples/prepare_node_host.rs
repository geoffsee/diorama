//! Explicit host preparation consumer. Optional fixture barriers never run in production main.
use diorama::host_container::ControllerName;
use diorama::host_preparation::{HostPreparation, HostPreparationStatus, prepare_node_host};
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
    runtime.block_on(prepare(&config))
}
fn emit(value: &serde_json::Value) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{value}")?;
    out.flush()
}
fn render(report: &HostPreparation, pass: u8) -> serde_json::Value {
    let network = &report.network;
    let container = &report.container;
    serde_json::json!({
        "schema":1,"event":"result","pass":pass,"pid":std::process::id(),
        "status":format!("{:?}",report.status),"shared_effects_possible":report.shared_effects_possible,
        "network": {
            "status":format!("{:?}",network.status),"assessment":format!("{:?}",network.assessment.status),
            "runtime":format!("{:?}",network.assessment.runtime),
            "family":network.assessment.constrained.as_ref().map(|facts| format!("{:?}",facts.module_family)),
            "modules":network.modules.iter().map(|step| serde_json::json!({
                "name":step.module.name(),"outcome":format!("{:?}",step.command.outcome),
                "spawned":step.command.cleanup.spawned,"joined":step.command.cleanup.thread_joined,
                "reaped":step.command.cleanup.leader_reaped,"ownership_lost":step.command.cleanup.ownership_lost,
                "exit":step.command.cleanup.exit.map(|exit| exit.code),
                "after":step.after.as_ref().map(|after| serde_json::json!({
                    "loaded":format!("{:?}",after.loaded),"builtin_index":format!("{:?}",after.builtin_index),
                    "available_index":format!("{:?}",after.available_index),
                })),
            })).collect::<Vec<_>>(),
            "ipv6":network.ipv6.iter().map(|step|serde_json::json!({"path":step.control.path(),"outcome":format!("{:?}",step.outcome)})).collect::<Vec<_>>(),
        },
        "container": {
            "status":format!("{:?}",container.status),"layout":container.layout.map(|v|format!("{v:?}")),
            "mount":container.mount.as_ref().map(mutation),"init":container.init.as_ref().map(mutation),
            "migration":container.migration.as_ref().map(mutation),
            "available":container.available.iter().map(ControllerName::as_str).collect::<Vec<_>>(),
            "enabled_before":container.enabled_before.iter().map(ControllerName::as_str).collect::<Vec<_>>(),
            "enabled_after":container.enabled_after.as_ref().map(|result| match result {
                Ok(names)=>serde_json::json!({"names":names.iter().map(ControllerName::as_str).collect::<Vec<_>>()}),
                Err(error)=>serde_json::json!({"error":format!("{error:?}")}),
            }),
            "missing_after":container.missing_after.iter().map(ControllerName::as_str).collect::<Vec<_>>(),
            "attempts":container.controller_attempts.iter().map(|attempt|serde_json::json!({
                "controllers":attempt.controllers.iter().map(ControllerName::as_str).collect::<Vec<_>>(),"mutation":mutation(&attempt.mutation),
            })).collect::<Vec<_>>(),
            "shared_effects_possible":container.shared_effects_possible,
        },
    })
}
fn mutation(value: &diorama::host_container::Mutation) -> serde_json::Value {
    serde_json::json!({"attempted":value.attempted,"result":format!("{:?}",value.result)})
}
#[cfg(unix)]
struct Stop {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    deadline: tokio::time::Instant,
    latched: bool,
}
#[cfg(unix)]
impl Stop {
    fn new() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            deadline: tokio::time::Instant::now() + std::time::Duration::from_mins(3),
            latched: false,
        })
    }
    async fn wait(&mut self) {
        if !self.latched {
            tokio::select! { biased;
                _ = self.interrupt.recv() => {},
                _ = self.terminate.recv() => {},
                () = tokio::time::sleep_until(self.deadline) => {},
            }
            self.latched = true;
        }
    }
}
#[cfg(target_os = "linux")]
fn nonblocking_stdin() -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(io::stdin())?;
    rustix::fs::fcntl_setfl(io::stdin(), flags | rustix::fs::OFlags::NONBLOCK)?;
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn nonblocking_stdin() -> io::Result<()> {
    Err(io::Error::other("fixture protocol requires Linux"))
}
#[cfg(target_os = "linux")]
fn byte() -> io::Result<Option<u8>> {
    let mut value = [0_u8; 1];
    match rustix::io::read(io::stdin(), &mut value) {
        Ok(0) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "protocol EOF")),
        Ok(_) => Ok(Some(value[0])),
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => Ok(None),
        Err(error) => Err(error.into()),
    }
}
#[cfg(not(target_os = "linux"))]
fn byte() -> io::Result<Option<u8>> {
    Err(io::Error::other("fixture protocol requires Linux"))
}
#[cfg(unix)]
async fn gate(stop: &mut Stop, expected: u8) -> &'static str {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        tokio::select! { biased;
            () = stop.wait() => return "cancelled",
            () = tokio::time::sleep_until(deadline) => {stop.latched=true;return "timeout";},
            () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {},
        }
        match byte() {
            Ok(Some(value)) if value == expected => return "accepted",
            Ok(Some(_)) => {
                stop.latched = true;
                return "wrong_byte";
            },
            Ok(None) => {},
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                stop.latched = true;
                return "eof";
            },
            Err(_) => {
                stop.latched = true;
                return "read_failed";
            },
        }
    }
}
async fn publish_or_quiet<'a>(
    status: HostPreparationStatus,
    observers: impl Iterator<Item = &'a diorama_supervisor::process::ProcessCleanup>,
    publish: impl FnOnce() -> io::Result<()>,
) -> io::Result<Option<u8>> {
    if status == HostPreparationStatus::CleanupIncomplete {
        // Observation only: one aggregate grace, no PID reacquisition or signals.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        for observer in observers {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let _ = observer.wait(remaining).await;
        }
        return Ok(Some(2));
    }
    publish()?;
    Ok((status != HostPreparationStatus::Completed).then_some(1))
}
#[cfg(unix)]
async fn prepare(config: &diorama_config::ValidatedConfig) -> io::Result<u8> {
    let fixture =
        std::env::var_os("diorama_CONTAINER_FIXTURE_PROTOCOL").is_some_and(|value| value == "1");
    let mut stop = Stop::new()?;
    if fixture {
        nonblocking_stdin()?;
        emit(&serde_json::json!({"schema":1,"event":"READY","pid":std::process::id()}))?;
        let reason = gate(&mut stop, b'G').await;
        if reason != "accepted" {
            emit(
                &serde_json::json!({"schema":1,"event":"protocol_failure","phase":"READY","reason":reason,"preparation_started":false,"shared_effects_possible":false}),
            )?;
            return Ok(1);
        }
    }
    let mut effects = false;
    for pass in 1..=2 {
        // The operation is always awaited. Deadline/signals request cancellation inside
        // it, keeping listeners and process cleanup ownership alive through return.
        let report = prepare_node_host(config, stop.wait()).await;
        let observers = report
            .network
            .assessment
            .version
            .as_ref()
            .and_then(|version| version.observer.as_ref())
            .into_iter()
            .chain(
                report
                    .network
                    .modules
                    .iter()
                    .filter_map(|step| step.command.observer.as_ref()),
            );
        if let Some(code) =
            publish_or_quiet(report.status, observers, || emit(&render(&report, pass))).await?
        {
            return Ok(code);
        }
        effects |= report.shared_effects_possible;
        if !fixture {
            return Ok(0);
        }
        let (phase, expected) = if pass == 1 {
            ("FIRST", b'R')
        } else {
            ("SECOND", b'Q')
        };
        emit(&serde_json::json!({"schema":1,"event":phase,"pid":std::process::id()}))?;
        let reason = gate(&mut stop, expected).await;
        if reason != "accepted" {
            emit(
                &serde_json::json!({"schema":1,"event":"protocol_failure","phase":phase,"reason":reason,"preparation_started":true,"shared_effects_possible":effects}),
            )?;
            return Ok(1);
        }
    }
    emit(&serde_json::json!({"schema":1,"event":"DONE","pid":std::process::id()}))?;
    Ok(0)
}
#[cfg(not(unix))]
async fn prepare(_: &diorama_config::ValidatedConfig) -> io::Result<u8> {
    Err(io::Error::other("unsupported platform"))
}
fn main() -> ExitCode {
    if let Ok(code) = run() {
        ExitCode::from(code)
    } else {
        eprintln!("host preparation consumer failed before a complete result");
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn uncertain_cleanup_is_quiet_terminal_even_when_observer_is_settled() {
        let (_adapter, observer) = diorama_supervisor::process::OwnedProcessAdapter::new(
            diorama_supervisor::process::ProcessCommand::new("must-never-start"),
            async { Ok(()) },
        );
        let published = std::cell::Cell::new(false);
        let result = publish_or_quiet(
            HostPreparationStatus::CleanupIncomplete,
            std::iter::once(&observer),
            || {
                published.set(true);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(result, Some(2));
        assert!(!published.get());
        assert!(!observer.snapshot().started);
    }
    #[tokio::test]
    async fn cancelled_result_publishes_once_and_is_terminal() {
        let published = std::cell::Cell::new(0);
        let result = publish_or_quiet(HostPreparationStatus::Cancelled, std::iter::empty(), || {
            published.set(published.get() + 1);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(result, Some(1));
        assert_eq!(published.get(), 1);
    }
}
