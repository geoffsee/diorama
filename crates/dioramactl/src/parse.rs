use crate::artifact::DEFAULT_VERSION;
use crate::completion::parse_shell;
use crate::contract::{
    CheckOptions, CompletionOptions, ConfigOptions, D2kOptions, DownloadOptions, InstallOptions,
    KubeconfigOptions, ResetOptions, UninstallOptions, UpgradeOptions,
};
use diorama_platform::Libc;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelpTopic {
    Root,
    Check,
    Version,
    Completion,
    Download,
    Install,
    Uninstall,
    Upgrade,
    Reset,
    Config,
    Kubeconfig,
    D2k,
    Addon,
    Token,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Help(HelpTopic),
    Version,
    UnknownHelp,
    Check(CheckOptions),
    Completion(CompletionOptions),
    Download(DownloadOptions),
    Install(InstallOptions),
    Uninstall(UninstallOptions),
    Upgrade(UpgradeOptions),
    Reset(ResetOptions),
    Config(ConfigOptions),
    Kubeconfig(KubeconfigOptions),
    D2k(D2kOptions),
    Addon(crate::addon::AddonOptions),
    Token(crate::token::TokenOptions),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    UnknownCommand,
    UnknownFlag,
    InvalidBoolean,
    TooManyArguments,
}

impl ParseError {
    pub fn message(self) -> &'static str {
        match self {
            Self::UnknownCommand => "unknown command; use dioramactl --help",
            Self::UnknownFlag => "unknown flag for this command; use --help",
            Self::InvalidBoolean => "invalid boolean flag value; use true or false",
            Self::TooManyArguments => "command input exceeds the supported byte or argument limit",
        }
    }
}

fn environment_bool(environment: &BTreeMap<String, String>, key: &str) -> bool {
    matches!(
        environment.get(key).map(String::as_str),
        Some("true" | "1" | "yes")
    )
}

fn scheme_proxy(environment: &BTreeMap<String, String>, url: Option<&str>) -> Option<String> {
    let key = if url.is_some_and(|url| {
        url.get(..7)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"))
    }) {
        "HTTP_PROXY"
    } else {
        "HTTPS_PROXY"
    };
    environment.get(key).cloned()
}

fn boolean(value: &str) -> Result<bool, ParseError> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(ParseError::InvalidBoolean),
    }
}

/// Parses management arguments only. No filesystem, environment or host probes.
/// Errors never reproduce attacker-controlled argument values.
#[allow(clippy::too_many_lines)]
pub fn parse_command(
    args: &[String],
    environment: &BTreeMap<String, String>,
) -> Result<Command, ParseError> {
    if args.len() > 256
        || args
            .iter()
            .map(String::len)
            .try_fold(0usize, usize::checked_add)
            .is_none_or(|n| n > 65536)
    {
        return Err(ParseError::TooManyArguments);
    }
    if args.first().map(String::as_str) == Some("addon") {
        if args.len() == 1 || args.iter().any(|a| a == "--help" || a == "-h") {
            return Ok(Command::Help(HelpTopic::Addon));
        }
        return crate::addon::parse(&args[1..]).map(Command::Addon);
    }
    if args.first().map(String::as_str) == Some("token") {
        if args.len() == 1 || args.iter().any(|a| a == "--help" || a == "-h") {
            return Ok(Command::Help(HelpTopic::Token));
        }
        return crate::token::parse(&args[1..]).map(Command::Token);
    }
    let mut topic = HelpTopic::Root;
    let mut command_index = None;
    let mut help_command = false;
    let mut cursor = 0;
    // Cobra finds a command before registering its help flag. Root flags without
    // an attached value consume the next token while locating the command.
    while let Some(arg) = args.get(cursor) {
        if arg == "--" {
            break;
        }
        if arg.starts_with('-') && arg != "-" {
            cursor += if arg.contains('=') { 1 } else { 2 };
            continue;
        }
        topic = match arg.as_str() {
            "check" => HelpTopic::Check,
            "version" => HelpTopic::Version,
            "help" => {
                help_command = true;
                HelpTopic::Root
            },
            "completion" => HelpTopic::Completion,
            "download" => HelpTopic::Download,
            "install" => HelpTopic::Install,
            "uninstall" => HelpTopic::Uninstall,
            "upgrade" => HelpTopic::Upgrade,
            "reset" => HelpTopic::Reset,
            "config" => HelpTopic::Config,
            "kubeconfig" => HelpTopic::Kubeconfig,
            "d2k" => HelpTopic::D2k,
            _ => return Err(ParseError::UnknownCommand),
        };
        command_index = Some(cursor);
        break;
    }

    let mut check_opts = CheckOptions {
        install_prerequisites: environment_bool(environment, "DIORAMA_INSTALL_PREREQS"),
        pprof: environment_bool(environment, "DIORAMA_PPROF_SERVER"),
    };

    let mut download_opts = DownloadOptions {
        run_mode: "service".into(),
        version: environment
            .get("DIORAMA_VERSION")
            .cloned()
            .unwrap_or_else(|| DEFAULT_VERSION.to_string()),
        path: environment
            .get("DIORAMA_DOWNLOAD_DIR")
            .map_or_else(|| PathBuf::from("."), PathBuf::from),
        arch: None,
        custom_url: environment
            .get("DIORAMA_BIN_URL")
            .or_else(|| environment.get("DIORAMA_CUSTOM_URL"))
            .cloned(),
        temp_dir: environment
            .get("DIORAMA_TEMP_DIR")
            .or_else(|| environment.get("TEMP_DIR"))
            .map(PathBuf::from),
        proxy: environment.get("DIORAMA_PROXY").cloned(),
        offline: environment_bool(environment, "DIORAMA_OFFLINE"),
        libc: None,
    };

    let mut install_opts = InstallOptions {
        version: environment
            .get("DIORAMA_VERSION")
            .cloned()
            .unwrap_or_else(|| DEFAULT_VERSION.to_string()),
        path: environment.get("DIORAMA_PATH").map_or_else(
            || PathBuf::from(crate::artifact::DEFAULT_DATA_PATH),
            PathBuf::from,
        ),
        apiserver_extra_sans: environment.get("DIORAMA_APISERVER_EXTRA_SANS").cloned(),
        node_ip: environment.get("DIORAMA_NODE_IP").cloned(),
        mtu: environment.get("DIORAMA_MTU").cloned(),
        portainer_edge_id: environment.get("DIORAMA_PORTAINER_EDGE_ID").cloned(),
        portainer_edge_key: environment.get("DIORAMA_PORTAINER_EDGE_KEY").cloned(),
        portainer_edge_async: environment_bool(environment, "DIORAMA_PORTAINER_EDGE_ASYNC"),
        portainer_edge_image: environment.get("DIORAMA_PORTAINER_EDGE_IMAGE").cloned(),
        local_storage: environment_bool(environment, "DIORAMA_LOCAL_STORAGE"),
        debug: environment_bool(environment, "DIORAMA_DEBUG"),
        pprof_server: environment_bool(environment, "DIORAMA_PPROF_SERVER"),
        run_mode: environment
            .get("DIORAMA_RUN_MODE")
            .cloned()
            .unwrap_or_else(|| "service".to_string()),
        proxy: environment.get("DIORAMA_PROXY").cloned(),
        offline_install: environment
            .get("DIORAMA_OFFLINE_INSTALL")
            .map(PathBuf::from),
        install_prereqs: environment_bool(environment, "DIORAMA_INSTALL_PREREQS"),
        d2k: environment_bool(environment, "DIORAMA_D2K"),
        d2k_namespace: environment
            .get("DIORAMA_D2K_NAMESPACE")
            .cloned()
            .unwrap_or_else(|| "d2k".to_string()),
        cpu_manager_policy: environment
            .get("DIORAMA_CPU_MANAGER_POLICY")
            .cloned()
            .unwrap_or_else(|| "none".to_string()),
        cpu_manager_policy_options: environment
            .get("DIORAMA_CPU_MANAGER_POLICY_OPTIONS")
            .cloned(),
        reserved_cpus: environment.get("DIORAMA_RESERVED_CPUS").cloned(),
        system_reserved: environment.get("DIORAMA_SYSTEM_RESERVED").cloned(),
        container_image: environment.get("DIORAMA_IMAGE").cloned(),
        container_ports: environment.get("DIORAMA_CONTAINER_PORTS").cloned(),
        name: environment
            .get("DIORAMA_NAME")
            .cloned()
            .unwrap_or_else(|| "diorama".to_string()),
        custom_url: environment
            .get("DIORAMA_BIN_URL")
            .or_else(|| environment.get("DIORAMA_CUSTOM_URL"))
            .cloned(),
        temp_dir: environment
            .get("DIORAMA_TEMP_DIR")
            .or_else(|| environment.get("TEMP_DIR"))
            .map(PathBuf::from),
    };

    let mut uninstall_opts = UninstallOptions::default();
    let mut upgrade_opts = UpgradeOptions::default();
    let mut reset_opts = ResetOptions::default();
    let mut config_opts = ConfigOptions {
        environment: environment.clone(),
        ..ConfigOptions::default()
    };
    let mut kubeconfig_opts = KubeconfigOptions::default();
    let mut d2k_opts = D2kOptions::default();

    let mut help = false;
    let mut positional = Vec::new();
    let mut literal = false;
    let mut i = 0;

    while i < args.len() {
        if Some(i) == command_index {
            i += 1;
            continue;
        }
        let arg = &args[i];
        if literal {
            positional.push(arg.as_str());
            i += 1;
            continue;
        }
        if arg == "--" {
            literal = true;
            i += 1;
            continue;
        }
        if !arg.starts_with('-') || arg == "-" {
            positional.push(arg.as_str());
            i += 1;
            continue;
        }

        // Share value handling between documented short and long options.
        let get_string_val = |val_opt: Option<&str>,
                              idx: &mut usize,
                              args: &[String]|
         -> Result<String, ParseError> {
            if let Some(v) = val_opt {
                Ok(v.to_string())
            } else if *idx + 1 < args.len() && !args[*idx + 1].starts_with('-') {
                *idx += 1;
                Ok(args[*idx].clone())
            } else {
                Err(ParseError::UnknownFlag)
            }
        };

        if let Some(flag) = arg.strip_prefix("--") {
            let (name, value) = flag
                .split_once('=')
                .map_or((flag, None), |(n, v)| (n, Some(v)));

            match name {
                "help" => {
                    help = value.map_or(Ok(true), boolean)?;
                },
                // Check flags
                "install-prereqs" if topic == HelpTopic::Check => {
                    check_opts.install_prerequisites = value.map_or(Ok(true), boolean)?;
                },
                "pprof-server" if topic == HelpTopic::Check => {
                    check_opts.pprof = value.map_or(Ok(true), boolean)?;
                },
                // Download flags
                "version" if topic == HelpTopic::Download => {
                    download_opts.version = get_string_val(value, &mut i, args)?;
                },
                "path" if topic == HelpTopic::Download => {
                    download_opts.path = PathBuf::from(get_string_val(value, &mut i, args)?);
                },
                "arch" if topic == HelpTopic::Download => {
                    download_opts.arch = Some(get_string_val(value, &mut i, args)?);
                },
                "custom-url" | "bin-url" if topic == HelpTopic::Download => {
                    download_opts.custom_url = Some(get_string_val(value, &mut i, args)?);
                },
                "temp-dir" if topic == HelpTopic::Download => {
                    download_opts.temp_dir =
                        Some(PathBuf::from(get_string_val(value, &mut i, args)?));
                },
                "proxy" if topic == HelpTopic::Download => {
                    download_opts.proxy = Some(get_string_val(value, &mut i, args)?);
                },
                "offline" if topic == HelpTopic::Download => {
                    download_opts.offline = value.map_or(Ok(true), boolean)?;
                },
                "glibc" if topic == HelpTopic::Download => {
                    if value.map_or(Ok(true), boolean)? {
                        download_opts.libc = Some(Libc::Glibc);
                    }
                },
                "musl" if topic == HelpTopic::Download => {
                    if value.map_or(Ok(true), boolean)? {
                        download_opts.libc = Some(Libc::Musl);
                    }
                },
                // Install flags
                "version" if topic == HelpTopic::Install => {
                    install_opts.version = get_string_val(value, &mut i, args)?;
                },
                "path" if topic == HelpTopic::Install => {
                    install_opts.path = PathBuf::from(get_string_val(value, &mut i, args)?);
                },
                "apiserver-extra-sans" if topic == HelpTopic::Install => {
                    install_opts.apiserver_extra_sans = Some(get_string_val(value, &mut i, args)?);
                },
                "node-ip" if topic == HelpTopic::Install => {
                    install_opts.node_ip = Some(get_string_val(value, &mut i, args)?);
                },
                "mtu" if topic == HelpTopic::Install => {
                    install_opts.mtu = Some(get_string_val(value, &mut i, args)?);
                },
                "portainer-edge-id" if topic == HelpTopic::Install => {
                    install_opts.portainer_edge_id = Some(get_string_val(value, &mut i, args)?);
                },
                "portainer-edge-key" if topic == HelpTopic::Install => {
                    install_opts.portainer_edge_key = Some(get_string_val(value, &mut i, args)?);
                },
                "portainer-edge-async" if topic == HelpTopic::Install => {
                    install_opts.portainer_edge_async = value.map_or(Ok(true), boolean)?;
                },
                "portainer-edge-image" if topic == HelpTopic::Install => {
                    install_opts.portainer_edge_image = Some(get_string_val(value, &mut i, args)?);
                },
                "local-storage" if topic == HelpTopic::Install => {
                    install_opts.local_storage = value.map_or(Ok(true), boolean)?;
                },
                "debug" if topic == HelpTopic::Install => {
                    install_opts.debug = value.map_or(Ok(true), boolean)?;
                },
                "pprof-server" if topic == HelpTopic::Install => {
                    install_opts.pprof_server = value.map_or(Ok(true), boolean)?;
                },
                "run-mode" if topic == HelpTopic::Install => {
                    install_opts.run_mode = get_string_val(value, &mut i, args)?;
                },
                "proxy" if topic == HelpTopic::Install => {
                    install_opts.proxy = Some(get_string_val(value, &mut i, args)?);
                },
                "offline-install" if topic == HelpTopic::Install => {
                    install_opts.offline_install =
                        Some(PathBuf::from(get_string_val(value, &mut i, args)?));
                },
                "install-prereqs" if topic == HelpTopic::Install => {
                    install_opts.install_prereqs = value.map_or(Ok(true), boolean)?;
                },
                "run-mode" if topic == HelpTopic::Download => {
                    download_opts.run_mode = get_string_val(value, &mut i, args)?;
                    if !matches!(download_opts.run_mode.as_str(), "service" | "container") {
                        return Err(ParseError::UnknownFlag);
                    }
                },
                "d2k" if topic == HelpTopic::Install => {
                    install_opts.d2k = value.map_or(Ok(true), boolean)?;
                },
                "d2k-namespace" if topic == HelpTopic::Install => {
                    install_opts.d2k_namespace = get_string_val(value, &mut i, args)?;
                },
                "cpu-manager-policy" if topic == HelpTopic::Install => {
                    install_opts.cpu_manager_policy = get_string_val(value, &mut i, args)?;
                },
                "cpu-manager-policy-options" if topic == HelpTopic::Install => {
                    install_opts.cpu_manager_policy_options =
                        Some(get_string_val(value, &mut i, args)?);
                },
                "reserved-cpus" if topic == HelpTopic::Install => {
                    install_opts.reserved_cpus = Some(get_string_val(value, &mut i, args)?);
                },
                "system-reserved" if topic == HelpTopic::Install => {
                    install_opts.system_reserved = Some(get_string_val(value, &mut i, args)?);
                },
                "image" if topic == HelpTopic::Install => {
                    install_opts.container_image = Some(get_string_val(value, &mut i, args)?);
                },
                "container-ports" if topic == HelpTopic::Install => {
                    install_opts.container_ports = Some(get_string_val(value, &mut i, args)?);
                },
                "name" if topic == HelpTopic::Install => {
                    install_opts.name = get_string_val(value, &mut i, args)?;
                },
                "custom-url" | "bin-url" if topic == HelpTopic::Install => {
                    install_opts.custom_url = Some(get_string_val(value, &mut i, args)?);
                },
                "temp-dir" if topic == HelpTopic::Install => {
                    install_opts.temp_dir =
                        Some(PathBuf::from(get_string_val(value, &mut i, args)?));
                },
                // Uninstall flags
                "path" if topic == HelpTopic::Uninstall => {
                    uninstall_opts.path = PathBuf::from(get_string_val(value, &mut i, args)?);
                },
                "purge" if topic == HelpTopic::Uninstall => {
                    uninstall_opts.purge = value.map_or(Ok(true), boolean)?;
                },
                "keep-config" if topic == HelpTopic::Uninstall => {
                    uninstall_opts.keep_config = value.map_or(Ok(true), boolean)?;
                },
                "force" if topic == HelpTopic::Uninstall => {
                    uninstall_opts.force = value.map_or(Ok(true), boolean)?;
                },
                // Upgrade flags
                "recover" if topic == HelpTopic::Upgrade => {
                    upgrade_opts.recover = value.map_or(Ok(true), boolean)?;
                },
                "version" if topic == HelpTopic::Upgrade => {
                    upgrade_opts.version = get_string_val(value, &mut i, args)?;
                },
                "path" if topic == HelpTopic::Upgrade => {
                    upgrade_opts.path = PathBuf::from(get_string_val(value, &mut i, args)?);
                },
                "offline-install" if topic == HelpTopic::Upgrade => {
                    upgrade_opts.offline_install =
                        Some(PathBuf::from(get_string_val(value, &mut i, args)?));
                },
                "custom-url" | "bin-url" if topic == HelpTopic::Upgrade => {
                    upgrade_opts.custom_url = Some(get_string_val(value, &mut i, args)?);
                },
                "proxy" if topic == HelpTopic::Upgrade => {
                    upgrade_opts.proxy = Some(get_string_val(value, &mut i, args)?);
                },
                // Reset flags
                "path" if topic == HelpTopic::Reset => {
                    reset_opts.path = PathBuf::from(get_string_val(value, &mut i, args)?);
                },
                "force" if topic == HelpTopic::Reset => {
                    reset_opts.force = value.map_or(Ok(true), boolean)?;
                },
                // Config flags
                "file" if topic == HelpTopic::Config => {
                    config_opts.file = Some(PathBuf::from(get_string_val(value, &mut i, args)?));
                },
                // Kubeconfig flags
                "path" if topic == HelpTopic::Kubeconfig => {
                    kubeconfig_opts.path = PathBuf::from(get_string_val(value, &mut i, args)?);
                },
                "name" if topic == HelpTopic::Kubeconfig => {
                    kubeconfig_opts.name = Some(get_string_val(value, &mut i, args)?);
                },
                "output" if topic == HelpTopic::Kubeconfig => {
                    kubeconfig_opts.output =
                        Some(PathBuf::from(get_string_val(value, &mut i, args)?));
                },
                // D2k flags
                "path" if topic == HelpTopic::D2k => {
                    d2k_opts.path = PathBuf::from(get_string_val(value, &mut i, args)?);
                },
                "output" if topic == HelpTopic::D2k => {
                    d2k_opts.output = Some(PathBuf::from(get_string_val(value, &mut i, args)?));
                },
                "name" if topic == HelpTopic::D2k => {
                    d2k_opts.name = Some(get_string_val(value, &mut i, args)?);
                },
                _ => return Err(ParseError::UnknownFlag),
            }
        } else {
            let (letters, value) = arg[1..]
                .split_once('=')
                .map_or((&arg[1..], None), |(n, v)| (n, Some(v)));
            match letters {
                "f" if topic == HelpTopic::Config => {
                    config_opts.file = Some(PathBuf::from(get_string_val(value, &mut i, args)?));
                },
                "o" if topic == HelpTopic::Kubeconfig => {
                    kubeconfig_opts.output =
                        Some(PathBuf::from(get_string_val(value, &mut i, args)?));
                },
                "o" if topic == HelpTopic::D2k => {
                    d2k_opts.output = Some(PathBuf::from(get_string_val(value, &mut i, args)?));
                },
                "name" if topic == HelpTopic::D2k => {
                    d2k_opts.name = Some(get_string_val(value, &mut i, args)?);
                },
                _ if !letters.is_empty() && letters.bytes().all(|b| b == b'h') => {
                    help = value.map_or(Ok(true), boolean)?;
                },
                _ => return Err(ParseError::UnknownFlag),
            }
        }
        i += 1;
    }

    if help {
        return Ok(Command::Help(topic));
    }
    if help_command {
        return Ok(match positional.first().copied() {
            None | Some("help") => Command::Help(HelpTopic::Root),
            Some("check") => Command::Help(HelpTopic::Check),
            Some("version") => Command::Help(HelpTopic::Version),
            Some("completion") => Command::Help(HelpTopic::Completion),
            Some("download") => Command::Help(HelpTopic::Download),
            Some("install") => Command::Help(HelpTopic::Install),
            Some("uninstall") => Command::Help(HelpTopic::Uninstall),
            Some("upgrade") => Command::Help(HelpTopic::Upgrade),
            Some("reset") => Command::Help(HelpTopic::Reset),
            Some("config") => Command::Help(HelpTopic::Config),
            Some("kubeconfig") => Command::Help(HelpTopic::Kubeconfig),
            Some("d2k") => Command::Help(HelpTopic::D2k),
            Some("addon") => Command::Help(HelpTopic::Addon),
            Some("token") => Command::Help(HelpTopic::Token),
            _ => Command::UnknownHelp,
        });
    }

    Ok(match topic {
        HelpTopic::Addon => Command::Help(HelpTopic::Addon),
        HelpTopic::Token => Command::Help(HelpTopic::Token),
        HelpTopic::Check => Command::Check(check_opts),
        HelpTopic::Version => Command::Version,
        HelpTopic::Root => Command::Help(HelpTopic::Root),
        HelpTopic::Completion => {
            let shell = positional.first().and_then(|s| parse_shell(s));
            let raw_arg = positional.first().map(|s| (*s).to_string());
            Command::Completion(CompletionOptions { shell, raw_arg })
        },
        HelpTopic::Download => {
            download_opts.proxy = download_opts
                .proxy
                .or_else(|| scheme_proxy(environment, download_opts.custom_url.as_deref()));
            Command::Download(download_opts)
        },
        HelpTopic::Install => {
            install_opts.proxy = install_opts
                .proxy
                .or_else(|| scheme_proxy(environment, install_opts.custom_url.as_deref()));
            Command::Install(install_opts)
        },
        HelpTopic::Uninstall => Command::Uninstall(uninstall_opts),
        HelpTopic::Upgrade => Command::Upgrade(upgrade_opts),
        HelpTopic::Reset => Command::Reset(reset_opts),
        HelpTopic::Config => {
            config_opts.subcommand = positional.first().map(|s| (*s).to_string());
            config_opts.key = positional.get(1).map(|s| (*s).to_string());
            config_opts.value = positional.get(2).map(|s| (*s).to_string());
            Command::Config(config_opts)
        },
        HelpTopic::Kubeconfig => {
            kubeconfig_opts.subcommand = positional.first().map(|s| (*s).to_string());
            Command::Kubeconfig(kubeconfig_opts)
        },
        HelpTopic::D2k => {
            d2k_opts.subcommand = positional.first().map(|s| (*s).to_string());
            Command::D2k(d2k_opts)
        },
    })
}
