//! Startup-only command adapter. Configuration and host IO are injected independently.
mod parse;

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use diorama_config::{
    ConfigError, DecodedConfig, EnvironmentMode, ErrorKind, HostContext, ResolutionWarning,
    ValidatedConfig, Warning,
};
use serde_json::json;

/// Read-only process inputs. Implementations must not prepare or start a node.
pub trait StartupInputs {
    fn read_config(&mut self, path: &Path) -> Result<Option<DecodedConfig>, ConfigError>;
    fn host(&mut self) -> io::Result<HostContext>;
}
pub enum StartupAction {
    Exit(u8),
    Start {
        config: Box<ValidatedConfig>,
        config_path: PathBuf,
        host: HostContext,
    },
}
impl std::fmt::Debug for StartupAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exit(code) => formatter.debug_tuple("Exit").field(code).finish(),
            Self::Start { .. } => formatter.write_str("Start(<resolved configuration>)"),
        }
    }
}
fn event(out: &mut dyn Write, level: &str, message: &str, error: Option<&str>) -> io::Result<()> {
    let mut value = json!({"level": level,"message":message});
    if let Some(error) = error {
        value["error"] = error.into();
    }
    writeln!(out, "{value}")
}
fn file_error(error: &ConfigError, path: &str) -> String {
    match error.kind {
        ErrorKind::Syntax => format!("parse {path}: error converting YAML to JSON: {error}"),
        ErrorKind::Version => format!(
            "{path}: {}: this version of KubeSolo does not understand (expected kubesolo.io/v1alpha1)",
            error.message
        ),
        ErrorKind::Type => format!(
            "parse {path}: cannot unmarshal string or incompatible value at {}: {}",
            error.path, error.message
        ),
        ErrorKind::Io if error.message.starts_with("Is a directory") => {
            format!("{}: is a directory", error.path)
        },
        _ => error.to_string(),
    }
}
fn resolution_error(error: &ConfigError) -> String {
    let message = match (error.path.as_str(), error.message.as_str()) {
        ("runtime.endpoint", "expected an absolute socket path or unix:// URL") => {
            "expected an absolute socket path or a unix:// URL".to_owned()
        },
        ("portainer.image", message) => format!("invalid image reference: {message}"),
        (
            "kubernetes.kubelet.cpuManager",
            "policy options and reserved CPUs require static policy",
        ) => "policy options and reserved CPUs require --cpu-manager-policy=static".to_owned(),
        ("kubernetes.kubelet.systemReserved", message)
            if message.starts_with("unsupported resource") =>
        {
            message.replacen(
                "unsupported resource",
                "unsupported --system-reserved resource",
                1,
            )
        },
        ("api.socketPath", "exceeds the 107-byte Unix socket path limit") => {
            "exceeds the 107-byte limit for Unix socket paths".to_owned()
        },
        ("d2k.enabled", "requires network.loadBalancer.enabled") => {
            return "d2k.enabled requires network.loadBalancer.enabled".into();
        },
        _ => error.message.clone(),
    };
    format!("{}: {message}", error.path)
}
fn warning_text(warning: &ResolutionWarning, path: &str) -> String {
    match warning {
        ResolutionWarning::File(Warning::MissingVersion) => {
            format!("{path} does not declare an apiVersion; assuming kubesolo.io/v1alpha1")
        },
        ResolutionWarning::File(Warning::UnexpectedKind(kind)) => format!(
            "{path} declares kind {kind:?}; KubeSolo only has Config, and read the file as one"
        ),
        ResolutionWarning::File(Warning::IgnoredSettings { unknown, duplicate }) => format!(
            "{path} contains settings this version of KubeSolo does not recognise, which were ignored: unknown={unknown:?}, duplicate={duplicate:?}"
        ),
        ResolutionWarning::Validation(warning) => format!("{}: {}", warning.field, warning.message),
    }
}
/// Resolve a command without starting services. Output failures propagate to the process boundary.
pub fn execute(
    args: &[String],
    environment: &BTreeMap<String, String>,
    version: &str,
    inputs: &mut dyn StartupInputs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<StartupAction> {
    let parsed = match parse::parse(args, environment) {
        Ok(parse::ParseResult::Help) => {
            stderr.write_all(include_bytes!("help.txt"))?;
            return Ok(StartupAction::Exit(0));
        },
        Ok(parse::ParseResult::Parsed(parsed)) => parsed,
        Err(error) => {
            writeln!(stderr, "diorama: error: {error}, try --help")?;
            return Ok(StartupAction::Exit(1));
        },
    };
    if parsed.version {
        writeln!(
            stderr,
            "{}",
            json!({"level":"info","version":version,"message":"kubesolo version"})
        )?;
        return Ok(StartupAction::Exit(0));
    }
    if parsed.full {
        event(
            stderr,
            "warn",
            "the --full flag (KUBESOLO_FULL) is deprecated and has no effect; KubeSolo always uses upstream Kubernetes defaults",
            None,
        )?;
    }
    let file = match inputs.read_config(Path::new(&parsed.config)) {
        Ok(file) => file,
        Err(error) => {
            event(
                stderr,
                "fatal",
                "failed to create service. check the logs for more information. exiting...",
                Some(&file_error(&error, &parsed.config)),
            )?;
            return Ok(StartupAction::Exit(1));
        },
    };
    let host = inputs.host()?;
    let resolved = match diorama_config::resolve_layers(
        file,
        environment,
        &parsed.flags,
        EnvironmentMode::Include,
        &host,
    ) {
        Ok(resolved) => resolved,
        Err(error) => {
            event(
                stderr,
                "fatal",
                "failed to create service. check the logs for more information. exiting...",
                Some(&resolution_error(&error)),
            )?;
            return Ok(StartupAction::Exit(1));
        },
    };
    for warning in &resolved.warnings {
        event(stderr, "warn", &warning_text(warning, &parsed.config), None)?;
    }
    if parsed.print {
        let text = diorama_config::render_effective_yaml(resolved.validated.config())
            .map_err(io::Error::other)?;
        stdout.write_all(text.as_bytes())?;
        return Ok(StartupAction::Exit(0));
    }
    Ok(StartupAction::Start {
        config: Box::new(resolved.validated),
        config_path: PathBuf::from(parsed.config),
        host,
    })
}

pub mod lifecycle_logs;

pub mod lifecycle_sink;

pub mod lifecycle_policy;

pub mod host_preflight;

pub mod host_network;

pub mod host_container;
pub mod host_preparation;

pub mod config_api;
pub mod metrics;
pub use config_api::{COMPONENT_CONFIG_API, ConfigApiAdapter, ConfigApiServer, clear_stale_socket};

pub mod runtime;
pub use runtime::{
    COMPONENT_APISERVER, COMPONENT_CONTAINERD, COMPONENT_CONTROLLER_MANAGER, COMPONENT_COREDNS,
    COMPONENT_DATASTORE, COMPONENT_EXTERNAL_CRI, COMPONENT_KUBELET, COMPONENT_LOCAL_PATH,
    COMPONENT_METRICS, COMPONENT_PORTAINER, COMPONENT_PROXY, NodeRuntime, RuntimeBuilder,
    RuntimeError, select_runtime_provider,
};

mod scheduler;

mod system_network;
