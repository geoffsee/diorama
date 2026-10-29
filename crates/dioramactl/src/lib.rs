//! Read-only management command boundary, independent from node startup parsing.
pub mod addon;
pub mod artifact;
pub mod bundle;
pub mod check_workflow;
pub mod cleanup;
pub mod completion;
pub mod config;
pub mod container;
pub mod container_fixtures;
pub mod container_image;
pub mod container_lifecycle;
pub mod container_ports;
pub mod contract;
pub mod d2k;
mod docker_command;
pub mod docker_engine;
pub mod download;
pub mod endpoints;
pub mod install;
pub mod kubeconfig;
pub mod migrate;
pub mod offline;
mod parse;
pub mod preparation;
pub mod service;
pub mod sudo_env;
pub mod upgrade;
mod upgrade_integrity;

pub use artifact::{
    ArtifactSelectionError, DEFAULT_DATA_PATH, DEFAULT_INSTALL_PATH, DEFAULT_RELEASE_BASE_URL,
    DEFAULT_VERSION, artifact_archive_name, artifact_download_url, installer_asset_name,
    resolve_target,
};
pub use completion::{Shell, generate_completion, parse_shell};
pub use config::{execute_config, resolve_config_path, resolve_socket_path};
pub use contract::{
    CheckOptions, CommandHandler, CompletionOptions, ConfigOptions, D2kOptions,
    DefaultCommandHandler, DownloadOptions, InstallOptions, KubeconfigOptions, ResetOptions,
    UninstallOptions, UpgradeOptions,
};
pub use download::execute_download;
pub use install::execute_install;
pub use kubeconfig::execute_kubeconfig;
pub use migrate::{
    ServiceMigrationResult, migrate_legacy_service, rewrite_service_content, service_file_path,
};
pub use parse::{Command, HelpTopic, ParseError, parse_command};
pub use service::{
    CustomServicePaths, InitBackend, LifecycleAction, LifecyclePlan, RunMode, ServiceConfig,
    ServiceDefinition, ServiceFile, UnsupportedTargetError, escape_openrc_double_quote,
    escape_systemd_env, generate_service_definition, plan_lifecycle_action,
    render_custom_definition, shell_quote,
};
pub use sudo_env::recover_sudo_env_from_bytes;

use diorama_platform::preflight::{
    CheckId, CheckStatus, Finding, PortAvailability, PreflightInputs, RuntimeOwnership,
    evaluate_preflight,
};
use diorama_platform::preflight_probe::SupplementalFacts;
use diorama_platform::{HostEvidence, Observation, PlatformError, ProbeFailure};
use std::collections::BTreeMap;
use std::io::{self, Write};

/// Injected host effects. Implementations must never prepare a host or stop listeners.
pub trait CheckInputs {
    fn discover(&mut self) -> Result<HostEvidence, PlatformError>;
    fn supplemental(&mut self) -> Result<SupplementalFacts, PlatformError>;
    fn ports(&mut self, pprof: bool) -> Result<[Observation<PortAvailability>; 4], PlatformError>;

    fn download_file(
        &mut self,
        _url: &str,
        _dest: &std::path::Path,
        _proxy: Option<&str>,
        _temp_dir: Option<&std::path::Path>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "download not supported by this CheckInputs implementation",
        ))
    }

    fn copy_self(&mut self, _dest: &std::path::Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "copy_self not supported by this CheckInputs implementation",
        ))
    }

    fn read_parent_environ(&mut self) -> io::Result<Vec<u8>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "read_parent_environ not supported by this CheckInputs implementation",
        ))
    }
}

pub fn help(topic: HelpTopic) -> &'static str {
    match topic {
        HelpTopic::Addon => crate::addon::HELP,
        HelpTopic::Root => {
            "diorama Kube management commands\n\nUsage:\n  dioramactl [command]\n\nCommands:\n  addon       Load an offline add-on pack\n  check       Check host prerequisites\n  completion  Generate shell completion scripts\n  config      Manage diorama configuration\n  d2k         Manage Docker-to-Kubernetes (d2k) API translator\n  download    Download the binary bundle for offline installation\n  install     Install diorama and configure the system service\n  kubeconfig  Manage kubeconfig context and cluster access\n  reset       Reset cluster data and restart services\n  uninstall   Uninstall diorama and remove associated system resources\n  upgrade     Upgrade diorama to a different version\n  version     Print version information\n\nUse dioramactl [command] --help for more information about a command.\n"
        },
        HelpTopic::Check => {
            "Check Linux host prerequisites; preparation requires explicit opt-in.\n\nUsage:\n  dioramactl check [flags]\n\nFlags:\n  -h, --help             Help for check\n      --install-prereqs  Install missing Alpine networking packages and enable its cgroups service\n      --pprof-server     Include pprof port 6060 in port checks\n"
        },
        HelpTopic::Version => {
            "Print dioramactl version information\n\nUsage:\n  dioramactl version\n"
        },
        HelpTopic::Completion => {
            "Generate shell completion scripts for dioramactl.\n\nUsage:\n  dioramactl completion [bash|zsh|fish|powershell]\n\nFlags:\n  -h, --help   Help for completion\n"
        },
        HelpTopic::Download => {
            concat!(
                "Download the binary bundle for offline installation.\n\nUsage:\n  dioramactl download [flags]\n\nFlags:\n      --arch string        Target architecture for the bundle (default: current host)\n                           Valid values: amd64, arm64, arm, riscv64, amd64-musl, arm64-musl, arm-musl, riscv64-musl\n      --bin-url string     Custom URL for binary download\n      --custom-url string  Custom URL for binary download\n      --glibc              Use glibc-based binary (default)\n  -h, --help               Help for download\n      --musl               Use musl-based binary\n      --offline            Compatibility flag; core downloads are always offline\n      --path string        Directory to download files into (default: \".\")\n      --run-mode string    Select host (service) or container bundle (default: service)\n      --proxy string       HTTP/HTTPS proxy URL\n      --temp-dir string    Temporary directory for download/extraction\n      --version string     Version to download (default: \"v",
                env!("CARGO_PKG_VERSION"),
                "\")\n"
            )
        },
        HelpTopic::Install => {
            concat!(
                "Install diorama and configure the system service.\n\nUsage:\n  dioramactl install [flags]\n\nFlags:\n      --container-ports string  User port mappings (default: loopback)\n      --bin-url string     Custom URL for binary download\n      --custom-url string  Custom URL for binary download\n      --temp-dir string    Temporary directory for download/extraction\n      --apiserver-extra-sans string   Comma-separated extra Subject Alternative Names for the API server certificate\n      --cpu-manager-policy string     CPU manager policy: none or static (default: \"none\")\n      --cpu-manager-policy-options string Comma-separated key=value options for the static policy\n      --d2k                           Enable the d2k Docker-to-Kubernetes API translator\n      --d2k-namespace string          Namespace d2k is deployed into (default: \"d2k\")\n      --debug                         Enable debug logging\n  -h, --help                          Help for install\n      --image string                  Container image to use in container mode\n      --install-prereqs               Automatically install missing OS prerequisites\n      --local-storage                 Enable the local-path storage provisioner\n      --mtu string                    Override auto-detected network MTU\n      --name string                   Instance name (default: \"diorama\")\n      --node-ip string                Override auto-detected node IP\n      --offline-install string        Path to a local tarball or binary to install instead of downloading\n      --path string                   Base directory for diorama data (default: \"/var/lib/diorama\")\n      --portainer-edge-async          Enable async mode for the Portainer edge agent\n      --portainer-edge-id string      Portainer edge agent ID\n      --portainer-edge-image string   Portainer edge agent image\n      --portainer-edge-key string     Portainer edge agent key\n      --pprof-server                  Enable the pprof HTTP profiling server\n      --proxy string                  HTTP/HTTPS proxy URL\n      --reserved-cpus string          CPUs reserved for the host\n      --run-mode string               How to run diorama: service (default), daemon, foreground, or container\n      --system-reserved string        Resources withheld from node allocatable\n      --version string                Version to install (default: \"v",
                env!("CARGO_PKG_VERSION"),
                "\")\n"
            )
        },
        HelpTopic::Uninstall => {
            "Uninstall diorama and remove associated system resources.\n\nUsage:\n  dioramactl uninstall [flags]\n\nFlags:\n  -h, --help          Help for uninstall\n      --force         Skip the confirmation prompt\n      --path string   Base directory for diorama data (default: \"/var/lib/diorama\")\n      --keep-config   Keep the configuration file\n      --purge         Remove all configuration and data\n"
        },
        HelpTopic::Upgrade => {
            "Upgrade diorama to a different version.\n\nUsage:\n  dioramactl upgrade [flags]\n\nFlags:\n  -h, --help                   Help for upgrade\n      --offline-install string Path to a local tarball or binary to install instead of downloading\n      --path string            Base directory for diorama data (default: \"/var/lib/diorama\")\n      --proxy string           HTTP/HTTPS proxy URL\n      --recover                Recover an interrupted upgrade from retained evidence\n      --version string         Version to upgrade to\n"
        },
        HelpTopic::Reset => {
            "Reset cluster data and restart services.\n\nUsage:\n  dioramactl reset [flags]\n\nFlags:\n  -h, --help          Help for reset\n      --force         Skip the confirmation prompt\n      --path string   Base directory for diorama data (default: \"/var/lib/diorama\")\n"
        },
        HelpTopic::Config => {
            "Manage diorama configuration.\n\nUsage:\n  dioramactl config [command]\n\nCommands:\n  edit        Edit configuration in default editor\n  get         Get configuration value\n  path        Print active configuration file path\n  set         Set configuration value\n\nFlags:\n  -f, --file string   Configuration file path\n  -h, --help          Help for config\n"
        },
        HelpTopic::Kubeconfig => {
            "Manage kubeconfig context and cluster access.\n\nUsage:\n  dioramactl kubeconfig [command]\n\nCommands:\n  fetch       Fetch cluster kubeconfig\n  merge       Merge cluster credentials into active kubeconfig\n  remove      Remove an instance context (requires --name)\n  route       Route an instance context to its published port (requires --name)\n  view        View raw cluster kubeconfig\n\nFlags:\n  -h, --help          Help for kubeconfig\n      --name string   Instance name for route/remove\n  -o, --output string Output file path\n      --path string   Base directory for diorama data (default: \"/var/lib/diorama\")\n"
        },
        HelpTopic::D2k => {
            "Manage Docker-to-Kubernetes (d2k) API translator.\n\nUsage:\n  dioramactl d2k [command]\n\nCommands:\n  fetch       Fetch client certificates and context for Docker CLI\n  install     Configure local Docker context\n\nFlags:\n  -h, --help          Help for d2k\n  -o, --output string Certificate output directory\n      --name string   Instance name (default: \"diorama\")\n      --path string   Base directory for diorama data (default: \"/var/lib/diorama\")\n"
        },
    }
}

/// Executes shell completion generation.
pub fn execute_completion(
    options: &CompletionOptions,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let Some(shell) = options.shell else {
        let err_detail = options.raw_arg.as_deref().map_or_else(
            || "accepts 1 arg(s), received 0".to_string(),
            |arg| format!("unsupported shell: {arg}"),
        );
        writeln!(
            stderr,
            "error: {err_detail}; valid values are bash, zsh, fish, powershell"
        )?;
        return Ok(1);
    };
    generate_completion(shell, stdout)?;
    Ok(0)
}

/// Parses and executes a management command with the default command handler.
pub fn execute(
    args: &[String],
    environment: &BTreeMap<String, String>,
    version: &str,
    inputs: &mut dyn CheckInputs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let mut default_handler = DefaultCommandHandler;
    execute_with_handler(
        args,
        environment,
        version,
        inputs,
        &mut default_handler,
        stdout,
        stderr,
    )
}

/// Parses and executes a management command with a custom command handler.
/// Diagnostics do not echo arguments, environment values, hostname, file contents
/// or raw OS errors. Output failures propagate.
pub fn execute_with_handler(
    args: &[String],
    environment: &BTreeMap<String, String>,
    version: &str,
    inputs: &mut dyn CheckInputs,
    handler: &mut dyn CommandHandler,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let mut env = environment.clone();
    if env.contains_key("SUDO_USER")
        && !env.contains_key("DIORAMA_PORTAINER_EDGE_KEY")
        && let Ok(bytes) = inputs.read_parent_environ()
    {
        recover_sudo_env_from_bytes(&mut env, &bytes);
    }

    match parse_command(args, &env) {
        Ok(Command::Help(topic)) => {
            stdout.write_all(help(topic).as_bytes())?;
            Ok(0)
        },
        Ok(Command::UnknownHelp) => {
            writeln!(stderr, "Unknown help topic")?;
            stderr.write_all(help(HelpTopic::Root).as_bytes())?;
            Ok(0)
        },
        Ok(Command::Addon(options)) => crate::addon::execute(&options, stdout, stderr),
        Ok(Command::Version) => {
            writeln!(stdout, "dioramactl {version}")?;
            Ok(0)
        },
        Ok(Command::Check(options)) => handler.execute_check(options, inputs, stderr),
        Ok(Command::Completion(options)) => handler.execute_completion(options, stdout, stderr),
        Ok(Command::Download(options)) => handler.execute_download(options, inputs, stdout, stderr),
        Ok(Command::Install(options)) => handler.execute_install(options, inputs, stdout, stderr),
        Ok(Command::Uninstall(options)) => {
            handler.execute_uninstall(options, inputs, stdout, stderr)
        },
        Ok(Command::Upgrade(options)) => handler.execute_upgrade(options, inputs, stdout, stderr),
        Ok(Command::Reset(options)) => handler.execute_reset(options, inputs, stdout, stderr),
        Ok(Command::Config(options)) => handler.execute_config(options, inputs, stdout, stderr),
        Ok(Command::Kubeconfig(options)) => {
            handler.execute_kubeconfig(options, inputs, stdout, stderr)
        },
        Ok(Command::D2k(options)) => handler.execute_d2k(options, inputs, stdout, stderr),
        Err(error) => {
            writeln!(stderr, "error: {}", error.message())?;
            Ok(1)
        },
    }
}

fn platform_failure(stderr: &mut dyn Write, stage: &str, error: PlatformError) -> io::Result<u8> {
    writeln!(
        stderr,
        "  [fail] {stage}: {error}; obtain supported host observations before retrying"
    )?;
    Ok(1)
}

fn check_name(id: CheckId) -> &'static str {
    match id {
        CheckId::Root => "root privileges",
        CheckId::Hostname => "hostname RFC 1123 compliance",
        CheckId::DockerConflict => "Docker conflict",
        CheckId::XtablesComment => "iptables xt_comment module",
        CheckId::AlpineNetworking => "nftables and iptables",
        CheckId::Cgroups => "cgroups controllers",
        CheckId::Ports => "required ports available",
    }
}

/// Runs supplied checks with no preparation and no port probe after an earlier failure.
pub fn execute_check(
    options: CheckOptions,
    inputs: &mut dyn CheckInputs,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    if options.install_prerequisites {
        writeln!(
            stderr,
            "error: the synchronous check API does not execute preparation; use the dioramactl executable or async preparation workflow"
        )?;
        return Ok(1);
    }
    writeln!(stderr, "\n  dioramactl  check\n\n  > Detecting system")?;
    let evidence = match inputs.discover() {
        Ok(value) => value,
        Err(error) => return platform_failure(stderr, "system detection", error),
    };
    if evidence.executable.os != "linux" {
        return platform_failure(stderr, "system detection", PlatformError::UnsupportedHost);
    }
    if !["x86_64", "aarch64", "arm", "riscv64"].contains(&evidence.executable.architecture.as_str())
    {
        return platform_failure(stderr, "system detection", PlatformError::UnsupportedTarget);
    }
    writeln!(stderr, "  [ok] System detected\n\n  > Pre-flight checks")?;
    let supplement = match inputs.supplemental() {
        Ok(value) => value,
        Err(error) => return platform_failure(stderr, "supplemental observations", error),
    };
    let mut policy = PreflightInputs {
        install_prerequisites: false,
        pprof: options.pprof,
        runtime: RuntimeOwnership::Managed,
        xt_comment_on_disk: supplement.xt_comment_on_disk,
        alpine_rc_service: supplement.alpine_rc_service,
        ports: [Observation::Unknown(ProbeFailure::Malformed); 4],
    };
    let initial = evaluate_preflight(&evidence, &policy);
    for finding in &initial.findings[..6] {
        if !render_finding(finding, stderr)? {
            return Ok(1);
        }
    }
    policy.ports = match inputs.ports(options.pprof) {
        Ok(value) => value,
        Err(error) => return platform_failure(stderr, "port observations", error),
    };
    let report = evaluate_preflight(&evidence, &policy);
    if !render_finding(&report.findings[6], stderr)? {
        return Ok(1);
    }
    writeln!(
        stderr,
        "  [ok] All 7 checks passed\n\n  Observed host prerequisites passed; ports are not reserved and runtime readiness is not established.\n"
    )?;
    Ok(0)
}

fn render_finding(finding: &Finding, stderr: &mut dyn Write) -> io::Result<bool> {
    if matches!(
        finding.status,
        CheckStatus::Pass | CheckStatus::NotApplicable
    ) {
        writeln!(stderr, "     {}", check_name(finding.check))?;
        Ok(true)
    } else {
        let severity_note = match finding.severity() {
            Some(diorama_platform::preflight::ErrorSeverity::Recoverable) => {
                " (recoverable limitation)"
            },
            Some(diorama_platform::preflight::ErrorSeverity::Uncertain) => {
                " (uncertain observation)"
            },
            Some(diorama_platform::preflight::ErrorSeverity::Fatal) => " (fatal error)",
            None => "",
        };
        writeln!(
            stderr,
            "  [fail] pre-flight checks: {}: {}{}",
            check_name(finding.check),
            reason_text(finding.reason),
            severity_note
        )?;
        if let Some(remediation) = finding.remediation {
            writeln!(stderr, "     {}", remediation_text(remediation))?;
        }
        for requirement in &finding.missing {
            writeln!(
                stderr,
                "     Missing or unavailable: {}",
                requirement_text(*requirement)
            )?;
        }
        if finding.uncertainty.is_some() {
            writeln!(
                stderr,
                "     The host observation is uncertain; verify it before proceeding."
            )?;
        }
        Ok(false)
    }
}

fn reason_text(reason: diorama_platform::preflight::Reason) -> &'static str {
    use diorama_platform::preflight::Reason;
    match reason {
        Reason::Satisfied => "requirements observed",
        Reason::NotAlpine => "not applicable on this system",
        Reason::MissingObservation => "required host information is missing",
        Reason::ProbeFailed => "required host information could not be read",
        Reason::RootRequired => "root privileges required",
        Reason::HostnameEmpty => "hostname is empty",
        Reason::HostnameTooLong => "hostname exceeds the length limit",
        Reason::HostnameEmptyLabel => "hostname contains an empty label",
        Reason::HostnameLabelTooLong => "hostname label exceeds the length limit",
        Reason::HostnameInvalidLabel => "hostname label is invalid",
        Reason::DockerSocketPresent => "Docker socket exists",
        Reason::DockerBinaryPresent => "Docker executable landmark exists",
        Reason::CommentSupportMissing => "xt_comment support was not observed",
        Reason::AlpineToolsMissing => "required Alpine networking tools are missing",
        Reason::AlpineCgroupsSetup => "Alpine cgroups service requires preparation",
        Reason::CgroupsAbsent => "cgroups filesystem was not observed",
        Reason::ControllersMissing => "required cgroup controllers are missing",
        Reason::PortsBindFailed => "a required TCP port could not be bound",
    }
}

fn remediation_text(remediation: diorama_platform::preflight::Remediation) -> &'static str {
    use diorama_platform::preflight::Remediation;
    match remediation {
        Remediation::RunAsRoot => "Run the check as root.",
        Remediation::ConfigureHostname => "Configure an RFC 1123 compliant hostname.",
        Remediation::ResolveDockerConflict => "Resolve the Docker conflict before proceeding.",
        Remediation::ProvideCommentSupport => "Provide kernel xt_comment support.",
        Remediation::InstallAlpineNetworking => {
            "Install the missing networking packages, or opt in with --install-prereqs."
        },
        Remediation::EnableAlpineCgroups => {
            "Enable Alpine's cgroups service, or opt in with --install-prereqs."
        },
        Remediation::EnableKernelControllers => "Enable the required kernel cgroup controllers.",
        Remediation::ResolvePortConflict => {
            "Resolve the port conflict or permissions problem; this check does not stop listeners."
        },
        Remediation::ObtainObservation => "Obtain a readable host observation and retry.",
        Remediation::RecheckAfterPreparation => "Recheck host observations after preparation.",
    }
}

fn requirement_text(requirement: diorama_platform::preflight::Requirement) -> &'static str {
    use diorama_platform::preflight::Requirement;
    match requirement {
        Requirement::Nftables => "nftables",
        Requirement::Iptables => "iptables",
        Requirement::Cpuset => "cpuset controller",
        Requirement::Cpu => "cpu controller",
        Requirement::Io => "io controller",
        Requirement::Memory => "memory controller",
        Requirement::Pids => "pids controller",
        Requirement::Port2379 => "TCP port 2379",
        Requirement::Port6443 => "TCP port 6443",
        Requirement::Port10443 => "TCP port 10443",
        Requirement::Port6060 => "TCP port 6060",
    }
}
