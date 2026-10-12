//! Lifecycle commands and plans for all service backends and execution modes.

use crate::service::model::{InitBackend, RunMode, ServiceConfig, ServiceDefinition};
use std::fmt;
use std::path::PathBuf;

/// Explicit errors for unsupported targets or execution modes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnsupportedTargetError {
    /// Service name is unsafe for generated paths or definitions.
    InvalidServiceName,
    /// An environment key is not a portable shell identifier.
    InvalidEnvironmentKey,
    /// Binary path must be absolute and free of control characters.
    InvalidBinaryPath,
    /// Service run mode requested, but no init backend was detected or specified.
    MissingInitBackend,
    /// Unknown or unsupported init system name.
    UnknownInitSystem(String),
    /// Unknown execution mode.
    UnknownRunMode(String),
    /// Process control is not implemented for this mode/action.
    UnsupportedAction {
        mode: RunMode,
        action: LifecycleAction,
    },
    /// Container mode cannot be managed via host init service commands.
    ContainerModeNotHostService,
    /// Non-Linux OS requested for Linux service installation.
    UnsupportedOperatingSystem(String),
}

impl fmt::Display for UnsupportedTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServiceName => f.write_str("invalid service name"),
            Self::InvalidEnvironmentKey => f.write_str("invalid environment key"),
            Self::InvalidBinaryPath => f.write_str("invalid service binary path"),
            Self::UnknownRunMode(mode) => write!(
                f,
                "unsupported run mode '{mode}'; supported modes: service, daemon, foreground, container"
            ),
            Self::UnsupportedAction { mode, action } => {
                write!(f, "{action:?} is not implemented for {mode} mode")
            },
            Self::MissingInitBackend => {
                write!(
                    f,
                    "init system could not be detected; specify an init backend explicitly"
                )
            },
            Self::UnknownInitSystem(name) => {
                write!(
                    f,
                    "unsupported init system '{name}'; supported backends: systemd, openrc, sysvinit, upstart, runit, s6"
                )
            },
            Self::ContainerModeNotHostService => {
                write!(
                    f,
                    "container run mode cannot be installed as a host service"
                )
            },
            Self::UnsupportedOperatingSystem(os) => {
                write!(
                    f,
                    "host service installation is only supported on Linux; current operating system is '{os}'"
                )
            },
        }
    }
}

impl std::error::Error for UnsupportedTargetError {}

/// Lifecycle operations that can be planned and executed on a service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LifecycleAction {
    Install,
    Uninstall,
    Start,
    Stop,
    Restart,
    Status,
}

/// A single command step within a lifecycle plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandStep {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandStep {
    pub fn new(program: impl Into<String>, args: &[&str]) -> Self {
        Self {
            program: program.into(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
        }
    }
}

/// Complete plan for performing a lifecycle action on a service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecyclePlan {
    pub action: LifecycleAction,
    pub backend: Option<InitBackend>,
    pub run_mode: RunMode,
    /// Definitions that must be written or removed.
    pub definition: Option<ServiceDefinition>,
    /// Commands to execute in order.
    pub commands: Vec<CommandStep>,
    /// Files or symlinks that should be cleaned up on uninstall.
    pub cleanup_paths: Vec<PathBuf>,
}

/// Produces a deterministic command and filesystem plan for a lifecycle action.
pub fn plan_lifecycle_action(
    action: LifecycleAction,
    config: &ServiceConfig,
) -> Result<LifecyclePlan, UnsupportedTargetError> {
    match config.run_mode {
        RunMode::Service => {
            let backend = config
                .backend
                .ok_or(UnsupportedTargetError::MissingInitBackend)?;
            plan_service_action(action, backend, config)
        },
        RunMode::Daemon => plan_daemon_action(action, config),
        RunMode::Foreground => plan_foreground_action(action, config),
        RunMode::Container => Err(UnsupportedTargetError::ContainerModeNotHostService),
    }
}

fn plan_service_action(
    action: LifecycleAction,
    backend: InitBackend,
    config: &ServiceConfig,
) -> Result<LifecyclePlan, UnsupportedTargetError> {
    match backend {
        InitBackend::Systemd => plan_systemd_action(action, config),
        InitBackend::OpenRc => plan_openrc_action(action, config),
        InitBackend::SysVinit => plan_sysvinit_action(action, config),
        InitBackend::Upstart => plan_upstart_action(action, config),
        InitBackend::Runit => plan_runit_action(action, config),
        InitBackend::S6 => plan_s6_action(action, config),
    }
}

fn plan_systemd_action(
    action: LifecycleAction,
    config: &ServiceConfig,
) -> Result<LifecyclePlan, UnsupportedTargetError> {
    let name = &config.name;
    let def = crate::service::generator::generate_service_definition(config)?;
    let backend = Some(InitBackend::Systemd);

    match action {
        LifecycleAction::Install => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: Some(def),
            commands: vec![
                CommandStep::new("systemctl", &["daemon-reload"]),
                CommandStep::new("systemctl", &["enable", name]),
                CommandStep::new("systemctl", &["restart", name]),
            ],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Uninstall => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![
                CommandStep::new("systemctl", &["stop", name]),
                CommandStep::new("systemctl", &["disable", name]),
                CommandStep::new("systemctl", &["daemon-reload"]),
            ],
            cleanup_paths: vec![def.primary_file],
        }),
        LifecycleAction::Start => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("systemctl", &["start", name])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Stop => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("systemctl", &["stop", name])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Restart => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("systemctl", &["restart", name])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Status => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("systemctl", &["status", name])],
            cleanup_paths: Vec::new(),
        }),
    }
}

fn plan_openrc_action(
    action: LifecycleAction,
    config: &ServiceConfig,
) -> Result<LifecyclePlan, UnsupportedTargetError> {
    let name = &config.name;
    let def = crate::service::generator::generate_service_definition(config)?;
    let backend = Some(InitBackend::OpenRc);

    match action {
        LifecycleAction::Install => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: Some(def),
            commands: vec![
                CommandStep::new("rc-update", &["add", name, "default"]),
                CommandStep::new("rc-service", &[name, "restart"]),
            ],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Uninstall => {
            let cleanup = def.files.iter().map(|file| file.path.clone()).collect();
            Ok(LifecyclePlan {
                action,
                backend,
                run_mode: config.run_mode,
                definition: None,
                commands: vec![
                    CommandStep::new("rc-service", &[name, "stop"]),
                    CommandStep::new("rc-update", &["del", name, "default"]),
                ],
                cleanup_paths: cleanup,
            })
        },
        LifecycleAction::Start => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("rc-service", &[name, "start"])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Stop => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("rc-service", &[name, "stop"])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Restart => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("rc-service", &[name, "restart"])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Status => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("rc-service", &[name, "status"])],
            cleanup_paths: Vec::new(),
        }),
    }
}

fn plan_sysvinit_action(
    action: LifecycleAction,
    config: &ServiceConfig,
) -> Result<LifecyclePlan, UnsupportedTargetError> {
    let name = &config.name;
    let def = crate::service::generator::generate_service_definition(config)?;
    let backend = Some(InitBackend::SysVinit);

    match action {
        LifecycleAction::Install => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: Some(def),
            commands: vec![
                CommandStep::new("update-rc.d", &[name, "defaults"]),
                CommandStep::new("service", &[name, "restart"]),
            ],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Uninstall => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![
                CommandStep::new("service", &[name, "stop"]),
                CommandStep::new("update-rc.d", &["-f", name, "remove"]),
            ],
            cleanup_paths: vec![def.primary_file],
        }),
        LifecycleAction::Start => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("service", &[name, "start"])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Stop => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("service", &[name, "stop"])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Restart => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("service", &[name, "restart"])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Status => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("service", &[name, "status"])],
            cleanup_paths: Vec::new(),
        }),
    }
}

fn plan_upstart_action(
    action: LifecycleAction,
    config: &ServiceConfig,
) -> Result<LifecyclePlan, UnsupportedTargetError> {
    let name = &config.name;
    let def = crate::service::generator::generate_service_definition(config)?;
    let backend = Some(InitBackend::Upstart);

    match action {
        LifecycleAction::Install => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: Some(def),
            commands: vec![
                CommandStep::new("initctl", &["reload-configuration"]),
                CommandStep::new("initctl", &["restart", name]),
            ],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Uninstall => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![
                CommandStep::new("initctl", &["stop", name]),
                CommandStep::new("initctl", &["reload-configuration"]),
            ],
            cleanup_paths: vec![def.primary_file],
        }),
        LifecycleAction::Start => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("initctl", &["start", name])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Stop => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("initctl", &["stop", name])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Restart => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("initctl", &["restart", name])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Status => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("initctl", &["status", name])],
            cleanup_paths: Vec::new(),
        }),
    }
}

fn plan_runit_action(
    action: LifecycleAction,
    config: &ServiceConfig,
) -> Result<LifecyclePlan, UnsupportedTargetError> {
    let name = &config.name;
    let def = crate::service::generator::generate_service_definition(config)?;
    let backend = Some(InitBackend::Runit);
    let service_link = def.symlinks.first().map_or_else(
        || PathBuf::from(format!("/var/service/{name}")),
        |(_, target)| target.clone(),
    );
    let service_dir = def.directories[0].0.to_string_lossy().into_owned();
    let service_link_path = service_link.to_string_lossy().into_owned();
    let mut cleanup_paths = vec![service_link];
    cleanup_paths.extend(def.files.iter().map(|file| file.path.clone()));
    cleanup_paths.extend(def.directories.iter().rev().map(|(dir, _)| dir.clone()));

    match action {
        LifecycleAction::Install => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: Some(def),
            commands: vec![CommandStep::new("sv", &["restart", &service_dir])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Uninstall => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![
                CommandStep::new("sv", &["-w", "7", "down", &service_dir]),
                CommandStep::new("rm", &["-f", "--", &service_link_path]),
                CommandStep::new("sv", &["-w", "7", "exit", &service_dir]),
            ],
            cleanup_paths,
        }),
        LifecycleAction::Start => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("sv", &["start", &service_dir])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Stop => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("sv", &["stop", &service_dir])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Restart => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("sv", &["restart", &service_dir])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Status => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("sv", &["status", &service_dir])],
            cleanup_paths: Vec::new(),
        }),
    }
}

fn plan_s6_action(
    action: LifecycleAction,
    config: &ServiceConfig,
) -> Result<LifecyclePlan, UnsupportedTargetError> {
    let name = &config.name;
    let def = crate::service::generator::generate_service_definition(config)?;
    let backend = Some(InitBackend::S6);
    let scan_link = def.symlinks.first().map_or_else(
        || PathBuf::from(format!("/etc/s6/adminsv/default/{name}")),
        |(_, target)| target.clone(),
    );
    let service_dir = def.directories.first().map_or_else(
        || PathBuf::from(format!("/etc/s6/sv/{name}")),
        |(dir, _)| dir.clone(),
    );
    let service_dir_str = service_dir.to_string_lossy().into_owned();
    let scan_dir = scan_link
        .parent()
        .expect("generated scan link has a parent");
    let scan_dir_str = scan_dir.to_string_lossy().into_owned();
    let mut cleanup_paths = vec![scan_link];
    cleanup_paths.extend(def.files.iter().map(|file| file.path.clone()));
    cleanup_paths.extend(def.directories.iter().rev().map(|(dir, _)| dir.clone()));

    match action {
        LifecycleAction::Install => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: Some(def),
            commands: vec![CommandStep::new("s6-svc", &["-u", &service_dir_str])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Uninstall => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![
                CommandStep::new("s6-svc", &["-wD", "-T", "7000", "-d", &service_dir_str]),
                CommandStep::new("s6-svunlink", &["-t", "7000", &scan_dir_str, name]),
                // svunlink reports success even on timeout: confirm supervisor absence.
                CommandStep::new(
                    "sh",
                    &[
                        "-c",
                        "s6-svok \"$1\"; status=$?; [ \"$status\" -eq 1 ]",
                        "diorama-supervisor-exit-check",
                        &service_dir_str,
                    ],
                ),
            ],
            cleanup_paths,
        }),
        LifecycleAction::Start => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("s6-svc", &["-u", &service_dir_str])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Stop => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("s6-svc", &["-d", &service_dir_str])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Restart => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("s6-svc", &["-r", &service_dir_str])],
            cleanup_paths: Vec::new(),
        }),
        LifecycleAction::Status => Ok(LifecyclePlan {
            action,
            backend,
            run_mode: config.run_mode,
            definition: None,
            commands: vec![CommandStep::new("s6-svstat", &[&service_dir_str])],
            cleanup_paths: Vec::new(),
        }),
    }
}

fn plan_daemon_action(
    action: LifecycleAction,
    config: &ServiceConfig,
) -> Result<LifecyclePlan, UnsupportedTargetError> {
    Err(UnsupportedTargetError::UnsupportedAction {
        mode: config.run_mode,
        action,
    })
}

fn plan_foreground_action(
    action: LifecycleAction,
    config: &ServiceConfig,
) -> Result<LifecyclePlan, UnsupportedTargetError> {
    Err(UnsupportedTargetError::UnsupportedAction {
        mode: config.run_mode,
        action,
    })
}
