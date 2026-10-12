//! Data models for service definitions and execution modes.

use crate::service::lifecycle::UnsupportedTargetError;
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

/// Supported init system backends for host service lifecycle management.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InitBackend {
    Systemd,
    OpenRc,
    SysVinit,
    Upstart,
    Runit,
    S6,
}

impl InitBackend {
    /// String identifier matching CLI and platform conventions.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::OpenRc => "openrc",
            Self::SysVinit => "sysvinit",
            Self::Upstart => "upstart",
            Self::Runit => "runit",
            Self::S6 => "s6",
        }
    }
}

impl FromStr for InitBackend {
    type Err = UnsupportedTargetError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name.trim().to_ascii_lowercase().as_str() {
            "systemd" => Ok(Self::Systemd),
            "openrc" | "open-rc" => Ok(Self::OpenRc),
            "sysvinit" | "sysv" | "sys-v" => Ok(Self::SysVinit),
            "upstart" => Ok(Self::Upstart),
            "runit" => Ok(Self::Runit),
            "s6" => Ok(Self::S6),
            _ => Err(UnsupportedTargetError::UnknownInitSystem(name.to_string())),
        }
    }
}

impl TryFrom<diorama_platform::InitSystem> for InitBackend {
    type Error = UnsupportedTargetError;

    fn try_from(init: diorama_platform::InitSystem) -> Result<Self, Self::Error> {
        match init {
            diorama_platform::InitSystem::Systemd => Ok(InitBackend::Systemd),
            diorama_platform::InitSystem::OpenRc => Ok(InitBackend::OpenRc),
            diorama_platform::InitSystem::SysV => Ok(InitBackend::SysVinit),
            diorama_platform::InitSystem::Upstart => Ok(InitBackend::Upstart),
            diorama_platform::InitSystem::Runit => Ok(InitBackend::Runit),
            diorama_platform::InitSystem::S6 => Ok(InitBackend::S6),
            diorama_platform::InitSystem::Unknown => {
                Err(UnsupportedTargetError::MissingInitBackend)
            },
        }
    }
}

impl fmt::Display for InitBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Execution run modes supported by diorama installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RunMode {
    /// Managed background daemon via host init service.
    Service,
    /// Background daemon process using PID file and log output.
    Daemon,
    /// Direct foreground process execution.
    Foreground,
    /// Container mode (e.g. Docker / Podman).
    Container,
}

impl RunMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Daemon => "daemon",
            Self::Foreground => "foreground",
            Self::Container => "container",
        }
    }
}

impl FromStr for RunMode {
    type Err = UnsupportedTargetError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name.trim().to_ascii_lowercase().as_str() {
            "service" => Ok(Self::Service),
            "daemon" => Ok(Self::Daemon),
            "foreground" => Ok(Self::Foreground),
            "container" => Ok(Self::Container),
            _ => Err(UnsupportedTargetError::UnknownRunMode(name.to_string())),
        }
    }
}

impl fmt::Display for RunMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A generated file that must be written to disk for service configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceFile {
    /// Absolute target path where file should be placed.
    pub path: PathBuf,
    /// Text content of the file.
    pub content: String,
    /// Unix file permission mode (e.g. 0o644 or 0o755).
    pub mode: u32,
}

/// Optional custom path overrides for non-standard roots, testing, or custom deployments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CustomServicePaths {
    /// Root directory prefix (e.g. `/` by default, or `/tmp/test-root`).
    pub root_prefix: Option<PathBuf>,
    /// Explicit service definition file path override.
    pub service_file_path: Option<PathBuf>,
    /// Explicit PID file path (default `/var/run/diorama.pid`).
    pub pid_file_path: Option<PathBuf>,
    /// Explicit log file path (default `/var/log/diorama.log`).
    pub log_file_path: Option<PathBuf>,
    /// Explicit environment file path (if applicable). `OpenRC` uses its canonical conf.d path.
    pub env_file_path: Option<PathBuf>,
}

/// Configuration inputs required to render a service definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Service name (default "diorama").
    pub name: String,
    /// Path to the node binary (e.g. `/usr/local/bin/diorama` or `/usr/local/bin/diorama`).
    pub binary_path: PathBuf,
    /// Command line arguments to pass to the binary when starting.
    pub args: Vec<String>,
    /// Environment variables to set for the service process.
    pub environment: BTreeMap<String, String>,
    /// Target run mode (service, daemon, foreground, container).
    pub run_mode: RunMode,
    /// Target init backend if `run_mode` is Service.
    pub backend: Option<InitBackend>,
    /// Custom path overrides.
    pub custom_paths: CustomServicePaths,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            name: "diorama".to_string(),
            binary_path: PathBuf::from("/usr/local/bin/diorama"),
            args: Vec::new(),
            environment: BTreeMap::new(),
            run_mode: RunMode::Service,
            backend: Some(InitBackend::Systemd),
            custom_paths: CustomServicePaths::default(),
        }
    }
}

/// Generated service definition containing all generated configuration files and symlinks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceDefinition {
    /// The init backend or run mode this definition applies to.
    pub backend: Option<InitBackend>,
    /// The primary service unit or script file.
    pub primary_file: PathBuf,
    /// All files that need to be created.
    pub files: Vec<ServiceFile>,
    /// Symlinks to create: (source, `target/link_name`).
    pub symlinks: Vec<(PathBuf, PathBuf)>,
    /// Directories that must exist with specific permissions: (path, mode).
    pub directories: Vec<(PathBuf, u32)>,
}
