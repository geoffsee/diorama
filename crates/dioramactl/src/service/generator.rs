//! Service definition generators for all supported backends.
//!
//! Replicates upstream `KubeSolo` service templates with precision:
//! - Systemd: unit template, `LimitNOFILE`, `KillMode=process`, Environment lines
//! - `OpenRC`: `#!/sbin/openrc-run`, unquoted `command_args`, `command_background=true`
//! - `SysVinit`: LSB init script headers, `start-stop-daemon`
//! - Upstart: respawn, respawn limit, script blocks
//! - runit: run script, svdir links
//! - s6: run and finish scripts, admin service directories
//! - daemon: PID file and log paths
//! - foreground: command execution spec

use crate::service::escaping::{
    escape_openrc_double_quote, escape_systemd_env, shell_quote, systemd_quote,
};
use crate::service::lifecycle::UnsupportedTargetError;
use crate::service::model::{
    CustomServicePaths, InitBackend, RunMode, ServiceConfig, ServiceDefinition, ServiceFile,
};
use std::fmt::Write;
use std::path::{Path, PathBuf};

/// Resolves a path under an optional root prefix.
fn resolve_prefixed(root: Option<&Path>, default_rel: &str) -> PathBuf {
    match root {
        Some(prefix) => {
            let clean = default_rel.strip_prefix('/').unwrap_or(default_rel);
            prefix.join(clean)
        },
        None => PathBuf::from(default_rel),
    }
}

/// Generates a service definition for the given configuration.
pub fn generate_service_definition(
    config: &ServiceConfig,
) -> Result<ServiceDefinition, UnsupportedTargetError> {
    if config.name.is_empty()
        || matches!(config.name.as_str(), "." | "..")
        || !config
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(UnsupportedTargetError::InvalidServiceName);
    }
    for key in config.environment.keys() {
        let mut bytes = key.bytes();
        if !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(UnsupportedTargetError::InvalidEnvironmentKey);
        }
    }
    let binary = config.binary_path.to_string_lossy();
    if !config.binary_path.is_absolute()
        || binary.chars().any(char::is_control)
        || binary.ends_with('\\')
    {
        return Err(UnsupportedTargetError::InvalidBinaryPath);
    }
    match config.run_mode {
        RunMode::Service => {
            let backend = config
                .backend
                .ok_or(UnsupportedTargetError::MissingInitBackend)?;
            match backend {
                InitBackend::Systemd => Ok(generate_systemd(config)),
                InitBackend::OpenRc => Ok(generate_openrc(config)),
                InitBackend::SysVinit => Ok(generate_sysvinit(config)),
                InitBackend::Upstart => Ok(generate_upstart(config)),
                InitBackend::Runit => Ok(generate_runit(config)),
                InitBackend::S6 => Ok(generate_s6(config)),
            }
        },
        RunMode::Daemon => Ok(generate_daemon(config)),
        RunMode::Foreground => Ok(generate_foreground(config)),
        RunMode::Container => Err(UnsupportedTargetError::ContainerModeNotHostService),
    }
}

/// Allows rendering custom definition overriding specific paths directly.
pub fn render_custom_definition(
    mut config: ServiceConfig,
    custom: CustomServicePaths,
) -> Result<ServiceDefinition, UnsupportedTargetError> {
    config.custom_paths = custom;
    generate_service_definition(&config)
}

// -----------------------------------------------------------------------------
// 1. Systemd
// -----------------------------------------------------------------------------

fn generate_systemd(config: &ServiceConfig) -> ServiceDefinition {
    let name = &config.name;
    let default_path = format!("/etc/systemd/system/{name}.service");
    let primary_file = config
        .custom_paths
        .service_file_path
        .clone()
        .unwrap_or_else(|| {
            resolve_prefixed(config.custom_paths.root_prefix.as_deref(), &default_path)
        });

    let mut env_lines = String::new();
    for (key, val) in &config.environment {
        let _ = writeln!(
            env_lines,
            "Environment=\"{}={}\"",
            key,
            escape_systemd_env(val)
        );
    }

    let mut exec_args = String::new();
    for arg in &config.args {
        exec_args.push(' ');
        exec_args.push_str(&systemd_quote(arg));
    }

    let binary = systemd_quote(&config.binary_path.to_string_lossy());

    let content = format!(
        r"[Unit]
Description=diorama Kubernetes Node
Documentation=https://github.com/geoffsee/diorama
After=network-online.target firewalld.service containerd.service
Wants=network-online.target

[Service]
Type=exec
KillMode=process
Delegate=yes
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s
ExecStart={binary}{exec_args}
{env_lines}[Install]
WantedBy=multi-user.target
"
    );

    ServiceDefinition {
        backend: Some(InitBackend::Systemd),
        primary_file: primary_file.clone(),
        files: vec![ServiceFile {
            path: primary_file,
            content,
            mode: 0o644,
        }],
        symlinks: Vec::new(),
        directories: Vec::new(),
    }
}

// -----------------------------------------------------------------------------
// 2. OpenRC
// -----------------------------------------------------------------------------

fn generate_openrc(config: &ServiceConfig) -> ServiceDefinition {
    let name = &config.name;
    let default_script_path = format!("/etc/init.d/{name}");
    let primary_file = config
        .custom_paths
        .service_file_path
        .clone()
        .unwrap_or_else(|| {
            resolve_prefixed(
                config.custom_paths.root_prefix.as_deref(),
                &default_script_path,
            )
        });

    let pid_file = config
        .custom_paths
        .pid_file_path
        .clone()
        .unwrap_or_else(|| {
            resolve_prefixed(
                config.custom_paths.root_prefix.as_deref(),
                &format!("/var/run/{name}.pid"),
            )
        });

    let default_conf_path = format!("/etc/conf.d/{name}");
    let conf_file = resolve_prefixed(
        config.custom_paths.root_prefix.as_deref(),
        &default_conf_path,
    );

    let mut command_args = String::new();
    for (i, arg) in config.args.iter().enumerate() {
        if i > 0 {
            command_args.push(' ');
        }
        command_args.push_str(&shell_quote(arg));
    }

    let command_args = escape_openrc_double_quote(&command_args);
    let binary = escape_openrc_double_quote(&config.binary_path.to_string_lossy());
    let pid_str = escape_openrc_double_quote(&pid_file.to_string_lossy());

    let script_content = format!(
        r#"#!/sbin/openrc-run
# Copyright 2026 diorama Authors
# Distributed under the terms of the Apache License, Version 2.0

name="{name}"
description="diorama Kubernetes Node"

command="{binary}"
command_args="{command_args}"
command_background=true
pidfile="{pid_str}"

depend() {{
    need net
    after firewall
    use logger
}}

start_pre() {{
    checkpath -d -m 0755 /var/run
}}
"#
    );

    let mut conf_content = String::from("# /etc/conf.d configuration for diorama\n");
    for (key, val) in &config.environment {
        let _ = writeln!(
            conf_content,
            "export {}=\"{}\"",
            key,
            escape_openrc_double_quote(val)
        );
    }

    let mut files = vec![ServiceFile {
        path: primary_file.clone(),
        content: script_content,
        mode: 0o755,
    }];

    if !config.environment.is_empty() {
        files.push(ServiceFile {
            path: conf_file,
            content: conf_content,
            mode: 0o644,
        });
    }

    ServiceDefinition {
        backend: Some(InitBackend::OpenRc),
        primary_file,
        files,
        symlinks: Vec::new(),
        directories: Vec::new(),
    }
}

// -----------------------------------------------------------------------------
// 3. SysVinit
// -----------------------------------------------------------------------------

fn generate_sysvinit(config: &ServiceConfig) -> ServiceDefinition {
    let name = &config.name;
    let default_script_path = format!("/etc/init.d/{name}");
    let primary_file = config
        .custom_paths
        .service_file_path
        .clone()
        .unwrap_or_else(|| {
            resolve_prefixed(
                config.custom_paths.root_prefix.as_deref(),
                &default_script_path,
            )
        });

    let pid_file = config
        .custom_paths
        .pid_file_path
        .clone()
        .unwrap_or_else(|| {
            resolve_prefixed(
                config.custom_paths.root_prefix.as_deref(),
                &format!("/var/run/{name}.pid"),
            )
        });

    let log_file = config
        .custom_paths
        .log_file_path
        .clone()
        .unwrap_or_else(|| {
            resolve_prefixed(
                config.custom_paths.root_prefix.as_deref(),
                &format!("/var/log/{name}.log"),
            )
        });

    let mut exec_args = String::new();
    for arg in &config.args {
        exec_args.push(' ');
        exec_args.push_str(&shell_quote(arg));
    }

    let mut env_exports = String::new();
    for (key, val) in &config.environment {
        let _ = writeln!(
            env_exports,
            "export {}=\"{}\"",
            key,
            escape_openrc_double_quote(val)
        );
    }

    let binary = config.binary_path.to_string_lossy();
    let pid_str = pid_file.to_string_lossy();
    let log_str = log_file.to_string_lossy();

    let content =
        render_sysvinit_script(name, &binary, &exec_args, &pid_str, &log_str, &env_exports);

    ServiceDefinition {
        backend: Some(InitBackend::SysVinit),
        primary_file: primary_file.clone(),
        files: vec![ServiceFile {
            path: primary_file,
            content,
            mode: 0o755,
        }],
        symlinks: Vec::new(),
        directories: Vec::new(),
    }
}

fn render_sysvinit_script(
    name: &str,
    binary: &str,
    exec_args: &str,
    pid_str: &str,
    log_str: &str,
    env_exports: &str,
) -> String {
    let launch = escape_openrc_double_quote(&format!(
        "exec {}{} >> {} 2>&1",
        shell_quote(binary),
        exec_args,
        shell_quote(log_str)
    ));
    let binary = escape_openrc_double_quote(binary);
    let exec_args = escape_openrc_double_quote(exec_args);
    let pid_str = escape_openrc_double_quote(pid_str);
    let log_str = escape_openrc_double_quote(log_str);
    format!(
        r#"#!/bin/sh
### BEGIN INIT INFO
# Provides:          {name}
# Required-Start:    $network $local_fs $remote_fs
# Required-Stop:     $network $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: diorama Kubernetes Node
# Description:       Single-node Kubernetes distribution service
### END INIT INFO

PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/bin
DESC="diorama Kubernetes Node"
NAME="{name}"
DAEMON="{binary}"
DAEMON_ARGS="{exec_args}"
PIDFILE="{pid_str}"
LOGFILE="{log_str}"
LAUNCH="{launch}"

case "$1" in
    status) ;;
    start|restart|force-reload) [ -x "$DAEMON" ] || exit 1 ;;
    *) [ -x "$DAEMON" ] || exit 0 ;;
esac

{env_exports}start() {{
    echo "Starting $DESC: $NAME"
    start-stop-daemon --start --background --make-pidfile \
        --pidfile "$PIDFILE" --startas /bin/sh -- -c "$LAUNCH"
}}

stop() {{
    echo "Stopping $DESC: $NAME"
    start-stop-daemon --stop --quiet --oknodo --pidfile "$PIDFILE" --retry 10 || return $?
    rm -f "$PIDFILE"
}}

status() {{
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "$NAME is running with PID $(cat "$PIDFILE")"
        return 0
    else
        echo "$NAME is stopped"
        return 3
    fi
}}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart|force-reload)
        stop && start
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {{start|stop|restart|force-reload|status}}" >&2
        exit 1
        ;;
esac

exit $?
"#
    )
}

// -----------------------------------------------------------------------------
// 4. Upstart
// -----------------------------------------------------------------------------

fn generate_upstart(config: &ServiceConfig) -> ServiceDefinition {
    let name = &config.name;
    let default_path = format!("/etc/init/{name}.conf");
    let primary_file = config
        .custom_paths
        .service_file_path
        .clone()
        .unwrap_or_else(|| {
            resolve_prefixed(config.custom_paths.root_prefix.as_deref(), &default_path)
        });

    let mut env_lines = String::new();
    for (key, val) in &config.environment {
        let _ = writeln!(
            env_lines,
            "env {}=\"{}\"",
            key,
            escape_openrc_double_quote(val)
        );
    }

    let mut exec_args = String::new();
    for arg in &config.args {
        exec_args.push(' ');
        exec_args.push_str(&shell_quote(arg));
    }

    let binary = shell_quote(&config.binary_path.to_string_lossy());

    let content = format!(
        r#"description "diorama Kubernetes Node"
author "diorama Authors"

start on runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit 10 5

limit nofile 1048576 1048576
kill timeout 60

{env_lines}exec {binary}{exec_args}
"#
    );

    ServiceDefinition {
        backend: Some(InitBackend::Upstart),
        primary_file: primary_file.clone(),
        files: vec![ServiceFile {
            path: primary_file,
            content,
            mode: 0o644,
        }],
        symlinks: Vec::new(),
        directories: Vec::new(),
    }
}

// -----------------------------------------------------------------------------
// 5. runit
// -----------------------------------------------------------------------------

fn generate_runit(config: &ServiceConfig) -> ServiceDefinition {
    let name = &config.name;
    let default_service_dir = format!("/etc/runit/sv/{name}");
    let service_dir = config
        .custom_paths
        .service_file_path
        .clone()
        .unwrap_or_else(|| {
            resolve_prefixed(
                config.custom_paths.root_prefix.as_deref(),
                &default_service_dir,
            )
        });

    let run_script = service_dir.join("run");
    let primary_file = run_script.clone();

    let mut env_exports = String::new();
    for (key, val) in &config.environment {
        let _ = writeln!(
            env_exports,
            "export {}=\"{}\"",
            key,
            escape_openrc_double_quote(val)
        );
    }

    let mut exec_args = String::new();
    for arg in &config.args {
        exec_args.push(' ');
        exec_args.push_str(&shell_quote(arg));
    }

    let binary = shell_quote(&config.binary_path.to_string_lossy());

    let run_content = format!(
        r"#!/bin/sh
exec 2>&1
{env_exports}exec {binary}{exec_args}
"
    );

    let default_var_service = format!("/var/service/{name}");
    let link_target = resolve_prefixed(
        config.custom_paths.root_prefix.as_deref(),
        &default_var_service,
    );

    ServiceDefinition {
        backend: Some(InitBackend::Runit),
        primary_file,
        files: vec![ServiceFile {
            path: run_script,
            content: run_content,
            mode: 0o755,
        }],
        symlinks: vec![(service_dir.clone(), link_target)],
        directories: vec![(service_dir, 0o755)],
    }
}

// -----------------------------------------------------------------------------
// 6. s6
// -----------------------------------------------------------------------------

fn generate_s6(config: &ServiceConfig) -> ServiceDefinition {
    let name = &config.name;
    let default_service_dir = format!("/etc/s6/sv/{name}");
    let service_dir = config
        .custom_paths
        .service_file_path
        .clone()
        .unwrap_or_else(|| {
            resolve_prefixed(
                config.custom_paths.root_prefix.as_deref(),
                &default_service_dir,
            )
        });

    let run_script = service_dir.join("run");
    let finish_script = service_dir.join("finish");
    let primary_file = run_script.clone();

    let mut env_exports = String::new();
    for (key, val) in &config.environment {
        let _ = writeln!(
            env_exports,
            "export {}=\"{}\"",
            key,
            escape_openrc_double_quote(val)
        );
    }

    let mut exec_args = String::new();
    for arg in &config.args {
        exec_args.push(' ');
        exec_args.push_str(&shell_quote(arg));
    }

    let binary = shell_quote(&config.binary_path.to_string_lossy());

    let run_content = format!(
        r"#!/bin/sh
exec 2>&1
{env_exports}exec {binary}{exec_args}
"
    );

    let finish_content = r#"#!/bin/sh
echo "Service exited with code $1, signal $2"
"#
    .to_string();

    let default_scan_dir = format!("/etc/s6/adminsv/default/{name}");
    let scan_link = resolve_prefixed(
        config.custom_paths.root_prefix.as_deref(),
        &default_scan_dir,
    );

    ServiceDefinition {
        backend: Some(InitBackend::S6),
        primary_file,
        files: vec![
            ServiceFile {
                path: run_script,
                content: run_content,
                mode: 0o755,
            },
            ServiceFile {
                path: finish_script,
                content: finish_content,
                mode: 0o755,
            },
        ],
        symlinks: vec![(service_dir.clone(), scan_link)],
        directories: vec![(service_dir, 0o755)],
    }
}

// -----------------------------------------------------------------------------
// 7. Daemon
// -----------------------------------------------------------------------------

fn generate_daemon(config: &ServiceConfig) -> ServiceDefinition {
    let name = &config.name;
    let pid_file = config
        .custom_paths
        .pid_file_path
        .clone()
        .unwrap_or_else(|| {
            resolve_prefixed(
                config.custom_paths.root_prefix.as_deref(),
                &format!("/var/run/{name}.pid"),
            )
        });

    let log_file = config
        .custom_paths
        .log_file_path
        .clone()
        .unwrap_or_else(|| {
            resolve_prefixed(
                config.custom_paths.root_prefix.as_deref(),
                &format!("/var/log/{name}.log"),
            )
        });

    ServiceDefinition {
        backend: None,
        primary_file: pid_file,
        files: Vec::new(),
        symlinks: Vec::new(),
        directories: vec![(
            log_file
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .to_path_buf(),
            0o755,
        )],
    }
}

// -----------------------------------------------------------------------------
// 8. Foreground
// -----------------------------------------------------------------------------

fn generate_foreground(config: &ServiceConfig) -> ServiceDefinition {
    ServiceDefinition {
        backend: None,
        primary_file: config.binary_path.clone(),
        files: Vec::new(),
        symlinks: Vec::new(),
        directories: Vec::new(),
    }
}
