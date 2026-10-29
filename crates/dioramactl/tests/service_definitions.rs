use dioramactl::{
    CustomServicePaths, InitBackend, LifecycleAction, RunMode, ServiceConfig,
    UnsupportedTargetError, escape_openrc_double_quote, escape_systemd_env,
    generate_service_definition, plan_lifecycle_action, render_custom_definition, shell_quote,
};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[test]
fn generated_backends_reject_unsafe_names_and_environment_keys() {
    for backend in [
        InitBackend::Systemd,
        InitBackend::OpenRc,
        InitBackend::SysVinit,
        InitBackend::Upstart,
        InitBackend::Runit,
        InitBackend::S6,
    ] {
        for name in [
            "",
            ".",
            "..",
            "../node",
            "node/name",
            "node\nexec id",
            "$(id)",
            "node'",
        ] {
            let config = ServiceConfig {
                name: name.into(),
                backend: Some(backend),
                ..ServiceConfig::default()
            };
            assert_eq!(
                generate_service_definition(&config).unwrap_err(),
                UnsupportedTargetError::InvalidServiceName
            );
        }
        for key in ["", "1A", "A=1;id", "A\nexec id", "A-B", "$(id)"] {
            let mut config = ServiceConfig {
                backend: Some(backend),
                ..ServiceConfig::default()
            };
            config.environment.insert(key.into(), "value".into());
            assert_eq!(
                generate_service_definition(&config).unwrap_err(),
                UnsupportedTargetError::InvalidEnvironmentKey
            );
        }
        let mut config = ServiceConfig {
            name: "node-1.test_name".into(),
            backend: Some(backend),
            ..ServiceConfig::default()
        };
        config.environment.insert("_VALID_1".into(), "value".into());
        assert!(generate_service_definition(&config).is_ok());
    }
}

#[test]
fn test_shell_quoting_and_sanitization() {
    assert_eq!(shell_quote(""), "''");
    assert_eq!(shell_quote("simple"), "'simple'");
    assert_eq!(shell_quote("with space"), "'with space'");
    assert_eq!(shell_quote("don't"), "'don'\\''t'");
    // Newline injection protection
    assert_eq!(shell_quote("arg1\narg2\r"), "'arg1arg2'");
}

#[test]
fn test_openrc_double_quote_escaping() {
    assert_eq!(
        escape_openrc_double_quote(r#"http://proxy:8080/foo?bar="1"&baz=$val`date`\#end"#),
        r#"http://proxy:8080/foo?bar=\"1\"&baz=\$val\`date\`\\#end"#
    );
    // Newlines stripped
    assert_eq!(
        escape_openrc_double_quote("val1\nval2\r\nval3"),
        "val1val2val3"
    );
}

#[test]
fn test_systemd_env_escaping() {
    assert_eq!(
        escape_systemd_env(r#"quote"slash\percent%end"#),
        r#"quote\"slash\\percent%%end"#
    );
    assert_eq!(escape_systemd_env("line1\nline2"), "line1line2");
}

#[test]
fn test_systemd_default_definition() {
    let mut env = BTreeMap::new();
    env.insert("HTTP_PROXY".to_string(), "http://10.0.0.1:8080".to_string());
    env.insert(
        "DIORAMA_EXTRA".to_string(),
        "percent%and\"quote".to_string(),
    );

    let config = ServiceConfig {
        name: "diorama".to_string(),
        binary_path: PathBuf::from("/usr/local/bin/diorama"),
        args: vec![
            "--debug".to_string(),
            "--run-mode".to_string(),
            "service".to_string(),
        ],
        environment: env,
        run_mode: RunMode::Service,
        backend: Some(InitBackend::Systemd),
        custom_paths: CustomServicePaths::default(),
    };

    let def = generate_service_definition(&config).expect("systemd service definition");
    assert_eq!(def.backend, Some(InitBackend::Systemd));
    assert_eq!(
        def.primary_file,
        PathBuf::from("/etc/systemd/system/diorama.service")
    );
    assert_eq!(def.files.len(), 1);

    let unit_file = &def.files[0];
    assert_eq!(
        unit_file.path,
        PathBuf::from("/etc/systemd/system/diorama.service")
    );
    assert_eq!(unit_file.mode, 0o644);

    let content = &unit_file.content;
    assert!(content.contains("[Unit]"));
    assert!(content.contains("Description=diorama Kubernetes Node"));
    assert!(content.contains("[Service]"));
    assert!(content.contains("KillMode=process"));
    assert!(content.contains("LimitNOFILE=1048576"));
    assert!(
        content.contains(
            "ExecStart=\"/usr/local/bin/diorama\" \"--debug\" \"--run-mode\" \"service\""
        )
    );
    assert!(content.contains("Environment=\"HTTP_PROXY=http://10.0.0.1:8080\"\n"));
    assert!(content.contains("Environment=\"DIORAMA_EXTRA=percent%%and\\\"quote\"\n"));
    assert!(content.contains("[Install]\nWantedBy=multi-user.target"));
}

#[test]
fn test_openrc_default_definition() {
    let mut env = BTreeMap::new();
    env.insert(
        "HTTPS_PROXY".to_string(),
        "http://proxy:3128/test".to_string(),
    );

    let config = ServiceConfig {
        name: "diorama".to_string(),
        binary_path: PathBuf::from("/opt/diorama/bin/diorama"),
        args: vec!["--node-ip".to_string(), "192.168.1.100".to_string()],
        environment: env,
        run_mode: RunMode::Service,
        backend: Some(InitBackend::OpenRc),
        custom_paths: CustomServicePaths::default(),
    };

    let def = generate_service_definition(&config).expect("openrc service definition");
    assert_eq!(def.backend, Some(InitBackend::OpenRc));
    assert_eq!(def.primary_file, PathBuf::from("/etc/init.d/diorama"));
    assert_eq!(def.files.len(), 2);

    let script = &def.files[0];
    assert_eq!(script.path, PathBuf::from("/etc/init.d/diorama"));
    assert_eq!(script.mode, 0o755);
    assert!(script.content.starts_with("#!/sbin/openrc-run"));
    assert!(script.content.contains("name=\"diorama\""));
    assert!(
        script
            .content
            .contains("command=\"/opt/diorama/bin/diorama\"")
    );
    assert!(
        script
            .content
            .contains("command_args=\"'--node-ip' '192.168.1.100'\"")
    );
    assert!(script.content.contains("command_background=true"));
    assert!(script.content.contains("pidfile=\"/var/run/diorama.pid\""));

    let conf = &def.files[1];
    assert_eq!(conf.path, PathBuf::from("/etc/conf.d/diorama"));
    assert_eq!(conf.mode, 0o644);
    assert!(
        conf.content
            .contains("export HTTPS_PROXY=\"http://proxy:3128/test\"")
    );
}

#[test]
fn test_sysvinit_default_definition() {
    let mut env = BTreeMap::new();
    env.insert("DIORAMA_ENV".to_string(), "production".to_string());

    let config = ServiceConfig {
        name: "diorama".to_string(),
        binary_path: PathBuf::from("/usr/local/bin/diorama"),
        args: vec!["--mtu".to_string(), "1450".to_string()],
        environment: env,
        run_mode: RunMode::Service,
        backend: Some(InitBackend::SysVinit),
        custom_paths: CustomServicePaths::default(),
    };

    let def = generate_service_definition(&config).expect("sysvinit definition");
    assert_eq!(def.backend, Some(InitBackend::SysVinit));
    assert_eq!(def.primary_file, PathBuf::from("/etc/init.d/diorama"));
    assert_eq!(def.files.len(), 1);

    let script = &def.files[0];
    assert_eq!(script.mode, 0o755);
    assert!(script.content.starts_with("#!/bin/sh"));
    assert!(script.content.contains("### BEGIN INIT INFO"));
    assert!(script.content.contains("# Provides:          diorama"));
    assert!(script.content.contains("DAEMON=\"/usr/local/bin/diorama\""));
    assert!(script.content.contains("DAEMON_ARGS=\" '--mtu' '1450'\""));
    assert!(script.content.contains("PIDFILE=\"/var/run/diorama.pid\""));
    assert!(script.content.contains("LOGFILE=\"/var/log/diorama.log\""));
    assert!(script.content.contains("start-stop-daemon --start"));
    assert!(script.content.contains("export DIORAMA_ENV=\"production\""));
}

#[test]
fn test_upstart_default_definition() {
    let mut env = BTreeMap::new();
    env.insert("FOO".to_string(), "bar".to_string());

    let config = ServiceConfig {
        name: "diorama".to_string(),
        binary_path: PathBuf::from("/usr/local/bin/diorama"),
        args: vec!["--local-storage".to_string()],
        environment: env,
        run_mode: RunMode::Service,
        backend: Some(InitBackend::Upstart),
        custom_paths: CustomServicePaths::default(),
    };

    let def = generate_service_definition(&config).expect("upstart definition");
    assert_eq!(def.backend, Some(InitBackend::Upstart));
    assert_eq!(def.primary_file, PathBuf::from("/etc/init/diorama.conf"));
    assert_eq!(def.files.len(), 1);

    let conf = &def.files[0];
    assert_eq!(conf.mode, 0o644);
    assert!(conf.content.contains("respawn"));
    assert!(conf.content.contains("respawn limit 10 5"));
    assert!(conf.content.contains("start on runlevel [2345]"));
    assert!(conf.content.contains("env FOO=\"bar\""));
    assert!(
        conf.content
            .contains("exec '/usr/local/bin/diorama' '--local-storage'")
    );
}

#[test]
fn test_runit_default_definition() {
    let mut env = BTreeMap::new();
    env.insert("MY_VAR".to_string(), "val".to_string());

    let config = ServiceConfig {
        name: "diorama".to_string(),
        binary_path: PathBuf::from("/usr/local/bin/diorama"),
        args: vec![],
        environment: env,
        run_mode: RunMode::Service,
        backend: Some(InitBackend::Runit),
        custom_paths: CustomServicePaths::default(),
    };

    let def = generate_service_definition(&config).expect("runit definition");
    assert_eq!(def.backend, Some(InitBackend::Runit));
    assert_eq!(def.primary_file, PathBuf::from("/etc/runit/sv/diorama/run"));
    assert_eq!(def.files.len(), 1);

    let run_file = &def.files[0];
    assert_eq!(run_file.mode, 0o755);
    assert!(run_file.content.starts_with("#!/bin/sh\nexec 2>&1\n"));
    assert!(run_file.content.contains("export MY_VAR=\"val\""));
    assert!(run_file.content.contains("exec '/usr/local/bin/diorama'"));

    assert_eq!(def.symlinks.len(), 1);
    assert_eq!(
        def.symlinks[0],
        (
            PathBuf::from("/etc/runit/sv/diorama"),
            PathBuf::from("/var/service/diorama")
        )
    );
    assert_eq!(
        def.directories,
        vec![(PathBuf::from("/etc/runit/sv/diorama"), 0o755)]
    );
}

#[test]
fn test_s6_default_definition() {
    let config = ServiceConfig {
        name: "diorama".to_string(),
        binary_path: PathBuf::from("/usr/local/bin/diorama"),
        args: vec!["--debug".to_string()],
        environment: BTreeMap::new(),
        run_mode: RunMode::Service,
        backend: Some(InitBackend::S6),
        custom_paths: CustomServicePaths::default(),
    };

    let def = generate_service_definition(&config).expect("s6 definition");
    assert_eq!(def.backend, Some(InitBackend::S6));
    assert_eq!(def.primary_file, PathBuf::from("/etc/s6/sv/diorama/run"));
    assert_eq!(def.files.len(), 2);

    let run = &def.files[0];
    assert_eq!(run.path, PathBuf::from("/etc/s6/sv/diorama/run"));
    assert_eq!(run.mode, 0o755);
    assert!(
        run.content
            .contains("exec '/usr/local/bin/diorama' '--debug'")
    );

    let finish = &def.files[1];
    assert_eq!(finish.path, PathBuf::from("/etc/s6/sv/diorama/finish"));
    assert_eq!(finish.mode, 0o755);
    assert!(finish.content.contains("Service exited with code $1"));

    assert_eq!(def.symlinks.len(), 1);
    assert_eq!(
        def.symlinks[0],
        (
            PathBuf::from("/etc/s6/sv/diorama"),
            PathBuf::from("/etc/s6/adminsv/default/diorama")
        )
    );
}

#[test]
fn test_daemon_and_foreground_modes() {
    let daemon_config = ServiceConfig {
        name: "test-daemon".to_string(),
        binary_path: PathBuf::from("/bin/node"),
        args: vec![],
        environment: BTreeMap::new(),
        run_mode: RunMode::Daemon,
        backend: None,
        custom_paths: CustomServicePaths::default(),
    };
    let def = generate_service_definition(&daemon_config).expect("daemon definition");
    assert_eq!(def.backend, None);
    assert_eq!(def.primary_file, PathBuf::from("/var/run/test-daemon.pid"));
    assert_eq!(def.files, <[dioramactl::ServiceFile; 0]>::default());
    assert_eq!(def.directories, vec![(PathBuf::from("/var/log"), 0o755)]);

    let fg_config = ServiceConfig {
        run_mode: RunMode::Foreground,
        ..daemon_config
    };
    let fg_def = generate_service_definition(&fg_config).expect("foreground definition");
    assert_eq!(fg_def.backend, None);
    assert_eq!(fg_def.primary_file, PathBuf::from("/bin/node"));
    assert_eq!(fg_def.files, <[dioramactl::ServiceFile; 0]>::default());
}

#[test]
fn test_custom_paths_and_root_prefix() {
    let custom = CustomServicePaths {
        root_prefix: Some(PathBuf::from("/custom/root")),
        service_file_path: None,
        pid_file_path: Some(PathBuf::from("/custom/run/my.pid")),
        log_file_path: Some(PathBuf::from("/custom/log/my.log")),
        env_file_path: None,
    };

    let config = ServiceConfig {
        name: "custom-svc".to_string(),
        binary_path: PathBuf::from("/usr/bin/custom-bin"),
        args: vec![],
        environment: BTreeMap::new(),
        run_mode: RunMode::Service,
        backend: Some(InitBackend::Systemd),
        custom_paths: custom,
    };

    let def = generate_service_definition(&config).expect("custom prefix systemd");
    assert_eq!(
        def.primary_file,
        PathBuf::from("/custom/root/etc/systemd/system/custom-svc.service")
    );

    // Test explicit service_file_path override
    let explicit_path = PathBuf::from("/tmp/test/service.unit");
    let custom2 = CustomServicePaths {
        service_file_path: Some(explicit_path.clone()),
        ..CustomServicePaths::default()
    };
    let rendered = render_custom_definition(config, custom2).expect("explicit render");
    assert_eq!(rendered.primary_file, explicit_path);
}

#[test]
fn test_unsupported_targets_fail_explicitly() {
    // Missing backend for service mode
    let cfg_missing = ServiceConfig {
        run_mode: RunMode::Service,
        backend: None,
        ..ServiceConfig::default()
    };
    let err = generate_service_definition(&cfg_missing).unwrap_err();
    assert_eq!(err, UnsupportedTargetError::MissingInitBackend);
    assert!(
        err.to_string()
            .contains("init system could not be detected")
    );

    // Container mode rejected for host service generator
    let cfg_container = ServiceConfig {
        run_mode: RunMode::Container,
        ..ServiceConfig::default()
    };
    let err_c = generate_service_definition(&cfg_container).unwrap_err();
    assert_eq!(err_c, UnsupportedTargetError::ContainerModeNotHostService);
    assert!(
        err_c
            .to_string()
            .contains("container run mode cannot be installed as a host service")
    );

    // Unknown init system string
    let unknown_err = UnsupportedTargetError::UnknownInitSystem("bogus-init".to_string());
    assert!(
        unknown_err
            .to_string()
            .contains("unsupported init system 'bogus-init'")
    );

    // Unsupported OS string
    let os_err = UnsupportedTargetError::UnsupportedOperatingSystem("darwin".to_string());
    assert!(os_err.to_string().contains(
        "host service installation is only supported on Linux; current operating system is 'darwin'"
    ));
}

#[test]
fn test_lifecycle_plans_for_all_backends() {
    let backends = [
        InitBackend::Systemd,
        InitBackend::OpenRc,
        InitBackend::SysVinit,
        InitBackend::Upstart,
        InitBackend::Runit,
        InitBackend::S6,
    ];

    let actions = [
        LifecycleAction::Install,
        LifecycleAction::Uninstall,
        LifecycleAction::Start,
        LifecycleAction::Stop,
        LifecycleAction::Restart,
        LifecycleAction::Status,
    ];

    for backend in backends {
        for action in actions {
            let config = ServiceConfig {
                name: "diorama".to_string(),
                backend: Some(backend),
                run_mode: RunMode::Service,
                ..ServiceConfig::default()
            };

            let plan = plan_lifecycle_action(action, &config).unwrap_or_else(|e| {
                panic!("failed planning {action:?} for backend {backend:?}: {e}")
            });
            assert_eq!(plan.action, action);
            assert_eq!(plan.backend, Some(backend));
            assert!(
                !plan.commands.is_empty(),
                "backend {backend:?} action {action:?} produced no commands"
            );

            match action {
                LifecycleAction::Install => {
                    assert!(plan.definition.is_some());
                },
                LifecycleAction::Uninstall => {
                    assert!(plan.definition.is_none());
                    assert_ne!(plan.cleanup_paths, <[std::path::PathBuf; 0]>::default());
                },
                _ => {
                    assert!(plan.definition.is_none());
                },
            }
        }
    }
}

#[test]
fn test_lifecycle_plan_command_specifics() {
    let config = ServiceConfig {
        name: "testsvc".to_string(),
        backend: Some(InitBackend::Systemd),
        run_mode: RunMode::Service,
        ..ServiceConfig::default()
    };

    // Systemd install
    let plan = plan_lifecycle_action(LifecycleAction::Install, &config).unwrap();
    assert_eq!(plan.commands.len(), 3);
    assert_eq!(plan.commands[0].program, "systemctl");
    assert_eq!(plan.commands[0].args, vec!["daemon-reload"]);
    assert_eq!(plan.commands[1].args, vec!["enable", "testsvc"]);
    assert_eq!(plan.commands[2].args, vec!["restart", "testsvc"]);

    // Systemd uninstall
    let plan = plan_lifecycle_action(LifecycleAction::Uninstall, &config).unwrap();
    assert_eq!(plan.commands[0].args, vec!["stop", "testsvc"]);
    assert_eq!(plan.commands[1].args, vec!["disable", "testsvc"]);
    assert_eq!(plan.commands[2].args, vec!["daemon-reload"]);
    assert_eq!(
        plan.cleanup_paths,
        vec![PathBuf::from("/etc/systemd/system/testsvc.service")]
    );

    // OpenRC install & uninstall
    let openrc_cfg = ServiceConfig {
        name: "testsvc".to_string(),
        backend: Some(InitBackend::OpenRc),
        run_mode: RunMode::Service,
        ..ServiceConfig::default()
    };
    let openrc_plan = plan_lifecycle_action(LifecycleAction::Install, &openrc_cfg).unwrap();
    assert_eq!(openrc_plan.commands[0].program, "rc-update");
    assert_eq!(
        openrc_plan.commands[0].args,
        vec!["add", "testsvc", "default"]
    );
    assert_eq!(openrc_plan.commands[1].program, "rc-service");
    assert_eq!(openrc_plan.commands[1].args, vec!["testsvc", "restart"]);

    let openrc_un = plan_lifecycle_action(LifecycleAction::Uninstall, &openrc_cfg).unwrap();
    assert_eq!(openrc_un.commands[0].program, "rc-service");
    assert_eq!(openrc_un.commands[0].args, vec!["testsvc", "stop"]);
    assert_eq!(openrc_un.commands[1].program, "rc-update");
    assert_eq!(
        openrc_un.commands[1].args,
        vec!["del", "testsvc", "default"]
    );

    // SysVinit
    let sysv_cfg = ServiceConfig {
        name: "testsvc".to_string(),
        backend: Some(InitBackend::SysVinit),
        run_mode: RunMode::Service,
        ..ServiceConfig::default()
    };
    let sysv_plan = plan_lifecycle_action(LifecycleAction::Install, &sysv_cfg).unwrap();
    assert_eq!(sysv_plan.commands[0].program, "update-rc.d");
    assert_eq!(sysv_plan.commands[0].args, vec!["testsvc", "defaults"]);

    // Upstart
    let upstart_cfg = ServiceConfig {
        name: "testsvc".to_string(),
        backend: Some(InitBackend::Upstart),
        run_mode: RunMode::Service,
        ..ServiceConfig::default()
    };
    let upstart_plan = plan_lifecycle_action(LifecycleAction::Install, &upstart_cfg).unwrap();
    assert_eq!(upstart_plan.commands[0].program, "initctl");
    assert_eq!(upstart_plan.commands[0].args, vec!["reload-configuration"]);

    // runit
    let runit_cfg = ServiceConfig {
        name: "testsvc".to_string(),
        backend: Some(InitBackend::Runit),
        run_mode: RunMode::Service,
        ..ServiceConfig::default()
    };
    let runit_plan = plan_lifecycle_action(LifecycleAction::Install, &runit_cfg).unwrap();
    assert_eq!(runit_plan.commands[0].program, "sv");
    assert_eq!(
        runit_plan.commands[0].args,
        vec!["restart", "/etc/runit/sv/testsvc"]
    );

    // s6
    let s6_cfg = ServiceConfig {
        name: "testsvc".to_string(),
        backend: Some(InitBackend::S6),
        run_mode: RunMode::Service,
        ..ServiceConfig::default()
    };
    let s6_plan = plan_lifecycle_action(LifecycleAction::Install, &s6_cfg).unwrap();
    assert_eq!(s6_plan.commands[0].program, "s6-svc");
    assert_eq!(s6_plan.commands[0].args, vec!["-u", "/etc/s6/sv/testsvc"]);
}

#[test]
fn lifecycle_rejects_unimplemented_process_control_and_reports_bad_mode() {
    let mut config = ServiceConfig::default();
    for mode in [RunMode::Daemon, RunMode::Foreground] {
        config.run_mode = mode;
        for action in [
            LifecycleAction::Install,
            LifecycleAction::Uninstall,
            LifecycleAction::Start,
            LifecycleAction::Stop,
            LifecycleAction::Restart,
            LifecycleAction::Status,
        ] {
            assert_eq!(
                plan_lifecycle_action(action, &config).unwrap_err(),
                UnsupportedTargetError::UnsupportedAction { mode, action }
            );
        }
    }
    assert!(
        "bogus"
            .parse::<RunMode>()
            .unwrap_err()
            .to_string()
            .contains("run mode")
    );
}

#[test]
fn assignments_do_not_execute_argument_substitutions() {
    let mut config = ServiceConfig {
        args: vec![r#"$(printf EXECUTED) `printf EXECUTED` $HOME "quote""#.into()],
        ..ServiceConfig::default()
    };
    for backend in [InitBackend::OpenRc, InitBackend::SysVinit] {
        config.backend = Some(backend);
        let def = generate_service_definition(&config).unwrap();
        let assignments = def.files[0]
            .content
            .lines()
            .filter(|line| line.starts_with("command_args=") || line.starts_with("DAEMON_ARGS="))
            .collect::<Vec<_>>()
            .join("\n");
        let variable = if backend == InitBackend::OpenRc {
            "command_args"
        } else {
            "DAEMON_ARGS"
        };
        let script = format!("{assignments}\nprintf '%s' \"${variable}\"");
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            shell_quote(&config.args[0])
        );
    }
}

#[test]
fn systemd_quotes_literals_and_shell_backends_execute_spaced_binary() {
    let mut config = ServiceConfig {
        backend: Some(InitBackend::Systemd),
        binary_path: PathBuf::from("/custom install/node"),
        args: vec![r#"%n ${UNSET} ' " \"#.into()],
        ..ServiceConfig::default()
    };
    let def = generate_service_definition(&config).unwrap();
    assert!(
        def.files[0]
            .content
            .contains(r#"ExecStart="/custom install/node" "%%n $${UNSET} ' \" \\""#)
    );
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("node with spaces");
    std::fs::write(&binary, "#!/bin/sh\nprintf '%s' \"$1\"\n").unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    config.binary_path = binary;
    config.args = vec!["literal argument".into()];
    for backend in [InitBackend::Runit, InitBackend::S6] {
        config.backend = Some(backend);
        let def = generate_service_definition(&config).unwrap();
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(&def.files[0].content)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"literal argument");
    }
}

#[test]
fn sysv_status_preserves_stopped_exit_code() {
    let mut config = ServiceConfig {
        backend: Some(InitBackend::SysVinit),
        binary_path: PathBuf::from("/bin/sh"),
        ..ServiceConfig::default()
    };
    let dir = tempfile::tempdir().unwrap();
    config.custom_paths.pid_file_path = Some(dir.path().join("absent.pid"));
    let def = generate_service_definition(&config).unwrap();
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&def.files[0].content)
        .arg("test")
        .arg("status")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    config.binary_path = dir.path().join("absent-node");
    let def = generate_service_definition(&config).unwrap();
    for (action, expected) in [("status", 3), ("start", 1), ("restart", 1)] {
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(&def.files[0].content)
            .arg("test")
            .arg(action)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected));
    }
}

#[test]
fn service_binary_paths_reject_ambiguous_or_control_character_inputs() {
    for path in ["relative/node", "/usr/bin/node\nextra", "/usr/bin/node\\"] {
        let config = ServiceConfig {
            binary_path: PathBuf::from(path),
            ..ServiceConfig::default()
        };
        assert_eq!(
            generate_service_definition(&config).unwrap_err(),
            UnsupportedTargetError::InvalidBinaryPath
        );
    }
}

#[test]
fn openrc_uses_the_canonical_conf_path_and_cleans_all_generated_files() {
    let root = tempfile::tempdir().unwrap();
    let config = ServiceConfig {
        backend: Some(InitBackend::OpenRc),
        environment: [("MODE".into(), "offline".into())].into(),
        custom_paths: CustomServicePaths {
            root_prefix: Some(root.path().into()),
            env_file_path: Some(root.path().join("custom.env")),
            ..CustomServicePaths::default()
        },
        ..ServiceConfig::default()
    };
    let def = generate_service_definition(&config).unwrap();
    assert!(
        def.files
            .iter()
            .any(|file| file.path == root.path().join("etc/conf.d/diorama"))
    );
    assert!(
        !def.files
            .iter()
            .any(|file| file.path == root.path().join("custom.env"))
    );
    let plan = plan_lifecycle_action(LifecycleAction::Uninstall, &config).unwrap();
    assert!(
        def.files
            .iter()
            .all(|file| plan.cleanup_paths.contains(&file.path))
    );
}

#[test]
fn supervised_directory_uninstall_stops_before_removing_every_owned_artifact() {
    for backend in [InitBackend::Runit, InitBackend::S6] {
        let config = ServiceConfig {
            backend: Some(backend),
            ..ServiceConfig::default()
        };
        let def = generate_service_definition(&config).unwrap();
        let plan = plan_lifecycle_action(LifecycleAction::Uninstall, &config).unwrap();
        for file in &def.files {
            assert!(plan.cleanup_paths.contains(&file.path));
        }
        for (directory, _) in &def.directories {
            assert!(plan.cleanup_paths.contains(directory));
        }
        for (_, link) in &def.symlinks {
            assert!(plan.cleanup_paths.contains(link));
        }
        if backend == InitBackend::Runit {
            let target = def.directories[0].0.to_string_lossy().into_owned();
            assert_eq!(plan.commands[0].args, ["-w", "7", "down", &target]);
            assert_eq!(plan.commands[1].program, "rm");
            assert_eq!(
                plan.commands[1].args[2],
                def.symlinks[0].1.to_string_lossy()
            );
            assert_eq!(plan.commands[2].args, ["-w", "7", "exit", &target]);
        } else {
            assert_eq!(plan.commands[1].program, "s6-svunlink");
            assert_eq!(plan.commands[1].args[0..2], ["-t", "7000"]);
            assert_eq!(plan.commands[2].program, "sh");
            assert!(plan.commands[2].args[1].contains("-eq 1"));
        }
    }
}

#[test]
fn s6_supervisor_exit_probe_rejects_a_live_supervisor_and_probe_errors() {
    let dir = tempfile::tempdir().unwrap();
    let probe = dir.path().join("s6-svok");
    std::fs::write(&probe, "#!/bin/sh\nexit \"$diorama_PROBE_CODE\"\n").unwrap();
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = ServiceConfig {
        backend: Some(InitBackend::S6),
        ..ServiceConfig::default()
    };
    let plan = plan_lifecycle_action(LifecycleAction::Uninstall, &config).unwrap();
    let check = &plan.commands[2];
    assert_eq!(check.program, "sh");
    for (code, absent) in [(0, false), (1, true), (111, false)] {
        let status = std::process::Command::new("/bin/sh")
            .args(&check.args)
            .env("PATH", dir.path())
            .env("diorama_PROBE_CODE", code.to_string())
            .status()
            .unwrap();
        assert_eq!(status.success(), absent, "probe exit {code}");
    }
}
