use diorama_platform::preflight::PortAvailability;
use diorama_platform::preflight_probe::SupplementalFacts;
use diorama_platform::{
    Architecture, ExecutableAbi, HostEvidence, Libc, NodeTarget, Observation, PlatformError,
    Privileges, ProbeFailure,
};
use dioramactl::{
    ArtifactSelectionError, CheckInputs, CheckOptions, Command, CommandHandler, CompletionOptions,
    ConfigOptions, D2kOptions, DefaultCommandHandler, DownloadOptions, InstallOptions,
    KubeconfigOptions, ParseError, ResetOptions, Shell, UninstallOptions, UpgradeOptions,
    artifact_archive_name, artifact_download_url, execute, execute_download, execute_with_handler,
    installer_asset_name, parse_command, parse_shell, recover_sudo_env_from_bytes, resolve_target,
};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).into()).collect()
}

struct TestInputs {
    os: String,
    arch: String,
    libc: Libc,
    download_url_called: Option<String>,
    download_dest_called: Option<PathBuf>,
    download_proxy_called: Option<String>,
    download_temp_dir_called: Option<PathBuf>,
    copy_self_dest_called: Option<PathBuf>,
    parent_environ_data: Option<Vec<u8>>,
    download_fails: bool,
    copy_self_fails: bool,
}

impl Default for TestInputs {
    fn default() -> Self {
        Self {
            os: "linux".into(),
            arch: "x86_64".into(),
            libc: Libc::Glibc,
            download_url_called: None,
            download_dest_called: None,
            download_proxy_called: None,
            download_temp_dir_called: None,
            copy_self_dest_called: None,
            parent_environ_data: None,
            download_fails: false,
            copy_self_fails: false,
        }
    }
}

impl CheckInputs for TestInputs {
    fn discover(&mut self) -> Result<HostEvidence, PlatformError> {
        let musl_linkers = if self.libc == Libc::Musl {
            vec!["/lib/ld-musl-x86_64.so.1".into()]
        } else {
            vec![]
        };
        Ok(HostEvidence {
            executable: ExecutableAbi {
                os: self.os.clone(),
                architecture: self.arch.clone(),
                environment: if self.libc == Libc::Musl {
                    "musl".into()
                } else {
                    "gnu".into()
                },
            },
            kernel: Observation::Unknown(ProbeFailure::Malformed),
            privileges: Observation::Present(Privileges {
                real_uid: 0,
                effective_uid: 0,
            }),
            hostname: Observation::Present("test-node".into()),
            container_environment_set: false,
            landmarks: BTreeMap::new(),
            musl_linkers: Observation::Present(musl_linkers),
            files: BTreeMap::new(),
            requested_paths: vec![],
        })
    }

    fn supplemental(&mut self) -> Result<SupplementalFacts, PlatformError> {
        Ok(SupplementalFacts {
            xt_comment_on_disk: Observation::Present(true),
            alpine_rc_service: Observation::Absent,
        })
    }

    fn ports(&mut self, _pprof: bool) -> Result<[Observation<PortAvailability>; 4], PlatformError> {
        Ok([
            Observation::Present(PortAvailability::Available),
            Observation::Present(PortAvailability::Available),
            Observation::Present(PortAvailability::Available),
            Observation::Present(PortAvailability::Available),
        ])
    }

    fn download_file(
        &mut self,
        url: &str,
        dest: &Path,
        proxy: Option<&str>,
        temp_dir: Option<&Path>,
    ) -> io::Result<()> {
        if self.download_fails {
            return Err(io::Error::other("mock download failure"));
        }
        self.download_url_called = Some(url.to_string());
        self.download_dest_called = Some(dest.to_path_buf());
        self.download_proxy_called = proxy.map(str::to_string);
        self.download_temp_dir_called = temp_dir.map(Path::to_path_buf);
        Ok(())
    }

    fn copy_self(&mut self, dest: &Path) -> io::Result<()> {
        if self.copy_self_fails {
            return Err(io::Error::other("mock copy_self failure"));
        }
        self.copy_self_dest_called = Some(dest.to_path_buf());
        Ok(())
    }

    fn read_parent_environ(&mut self) -> io::Result<Vec<u8>> {
        self.parent_environ_data
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no parent environ configured"))
    }
}

// -----------------------------------------------------------------------------
// 1. Artifact selection: 16 archive variants & naming
// -----------------------------------------------------------------------------

#[test]
fn test_all_16_archive_matrix_cells() {
    let version = "v1.1.8";
    let architectures = [
        (Architecture::Amd64, "amd64"),
        (Architecture::Arm64, "arm64"),
        (Architecture::ArmV7, "arm"),
        (Architecture::Riscv64, "riscv64"),
    ];
    let libcs = [(Libc::Glibc, ""), (Libc::Musl, "-musl")];
    let offline_options = [(false, ""), (true, "-offline")];

    let mut generated_names = Vec::new();

    for (arch, arch_name) in architectures {
        for (libc, libc_suffix) in libcs {
            for (offline, offline_suffix) in offline_options {
                let target = NodeTarget {
                    architecture: arch,
                    libc,
                };
                let archive_name = artifact_archive_name(version, target, offline);
                let expected = format!(
                    "diorama-{version}-linux-{arch_name}{libc_suffix}{offline_suffix}.tar.gz"
                );
                assert_eq!(archive_name, expected);
                generated_names.push(archive_name);
            }
        }
    }

    assert_eq!(generated_names.len(), 16);
    // Ensure all 16 are distinct
    let mut unique_names = generated_names.clone();
    unique_names.sort();
    unique_names.dedup();
    assert_eq!(unique_names.len(), 16);
}

#[test]
fn test_resolve_target_explicit_arch_values() {
    assert_eq!(
        resolve_target(Some("amd64"), None, None).unwrap(),
        NodeTarget {
            architecture: Architecture::Amd64,
            libc: Libc::Glibc
        }
    );
    assert_eq!(
        resolve_target(Some("amd64-musl"), None, None).unwrap(),
        NodeTarget {
            architecture: Architecture::Amd64,
            libc: Libc::Musl
        }
    );
    assert_eq!(
        resolve_target(Some("arm64"), None, None).unwrap(),
        NodeTarget {
            architecture: Architecture::Arm64,
            libc: Libc::Glibc
        }
    );
    assert_eq!(
        resolve_target(Some("arm64-musl"), None, None).unwrap(),
        NodeTarget {
            architecture: Architecture::Arm64,
            libc: Libc::Musl
        }
    );
    assert_eq!(
        resolve_target(Some("arm"), None, None).unwrap(),
        NodeTarget {
            architecture: Architecture::ArmV7,
            libc: Libc::Glibc
        }
    );
    assert_eq!(
        resolve_target(Some("armv7"), None, None).unwrap(),
        NodeTarget {
            architecture: Architecture::ArmV7,
            libc: Libc::Glibc
        }
    );
    assert_eq!(
        resolve_target(Some("arm-musl"), None, None).unwrap(),
        NodeTarget {
            architecture: Architecture::ArmV7,
            libc: Libc::Musl
        }
    );
    assert_eq!(
        resolve_target(Some("armv7-musl"), None, None).unwrap(),
        NodeTarget {
            architecture: Architecture::ArmV7,
            libc: Libc::Musl
        }
    );
    assert_eq!(
        resolve_target(Some("riscv64"), None, None).unwrap(),
        NodeTarget {
            architecture: Architecture::Riscv64,
            libc: Libc::Glibc
        }
    );
    assert_eq!(
        resolve_target(Some("riscv64-musl"), None, None).unwrap(),
        NodeTarget {
            architecture: Architecture::Riscv64,
            libc: Libc::Musl
        }
    );
}

#[test]
fn test_resolve_target_libc_override() {
    // Explicit libc override takes precedence over inferred libc from arch string
    assert_eq!(
        resolve_target(Some("amd64"), Some(Libc::Musl), None).unwrap(),
        NodeTarget {
            architecture: Architecture::Amd64,
            libc: Libc::Musl
        }
    );
    assert_eq!(
        resolve_target(Some("arm64-musl"), Some(Libc::Glibc), None).unwrap(),
        NodeTarget {
            architecture: Architecture::Arm64,
            libc: Libc::Glibc
        }
    );
}

#[test]
fn test_resolve_target_unsupported_arch() {
    let err = resolve_target(Some("i386"), None, None).unwrap_err();
    assert_eq!(err, ArtifactSelectionError::UnsupportedArch("i386".into()));
    assert!(err.to_string().contains("unsupported target arch \"i386\""));
}

#[test]
fn test_resolve_target_auto_detection_linux() {
    let mut inputs = TestInputs {
        os: "linux".into(),
        arch: "x86_64".into(),
        libc: Libc::Glibc,
        ..Default::default()
    };
    let evidence = inputs.discover().unwrap();
    let target = resolve_target(None, None, Some(&evidence)).unwrap();
    assert_eq!(
        target,
        NodeTarget {
            architecture: Architecture::Amd64,
            libc: Libc::Glibc
        }
    );

    let mut inputs_arm64 = TestInputs {
        os: "linux".into(),
        arch: "aarch64".into(),
        libc: Libc::Musl,
        ..Default::default()
    };
    let evidence_arm64 = inputs_arm64.discover().unwrap();
    let target_arm64 = resolve_target(None, None, Some(&evidence_arm64)).unwrap();
    assert_eq!(
        target_arm64,
        NodeTarget {
            architecture: Architecture::Arm64,
            libc: Libc::Musl
        }
    );
}

#[test]
fn test_resolve_target_darwin_requires_arch() {
    let mut inputs = TestInputs {
        os: "darwin".into(),
        arch: "aarch64".into(),
        libc: Libc::Glibc,
        ..Default::default()
    };
    let evidence = inputs.discover().unwrap();
    let err = resolve_target(None, None, Some(&evidence)).unwrap_err();
    assert_eq!(err, ArtifactSelectionError::DarwinRequiresArch);
    assert!(
        err.to_string()
            .contains("on macOS, diorama has no native binaries")
    );

    // Supplying explicit --arch on Darwin works
    let target = resolve_target(Some("arm64"), None, Some(&evidence)).unwrap();
    assert_eq!(
        target,
        NodeTarget {
            architecture: Architecture::Arm64,
            libc: Libc::Glibc
        }
    );
}

#[test]
fn test_resolve_target_missing_host_evidence() {
    let err = resolve_target(None, None, None).unwrap_err();
    assert_eq!(err, ArtifactSelectionError::MissingHostEvidence);
}

#[test]
fn test_artifact_urls_and_installer_asset_names() {
    let target = NodeTarget {
        architecture: Architecture::Amd64,
        libc: Libc::Glibc,
    };
    let archive = artifact_archive_name("v1.1.8", target, false);
    assert_eq!(archive, "diorama-v1.1.8-linux-amd64.tar.gz");

    let default_url = artifact_download_url("v1.1.8", &archive, None);
    assert_eq!(
        default_url,
        "https://github.com/geoffsee/diorama/releases/download/v1.1.8/diorama-v1.1.8-linux-amd64.tar.gz"
    );

    let custom_url =
        artifact_download_url("v1.1.8", &archive, Some("http://internal.repo/bin.tar.gz"));
    assert_eq!(custom_url, "http://internal.repo/bin.tar.gz");

    // Empty custom url falls back to default
    let empty_custom_url = artifact_download_url("v1.1.8", &archive, Some("   "));
    assert_eq!(empty_custom_url, default_url);

    assert_eq!(
        installer_asset_name("linux", Architecture::Amd64),
        "dioramactl-linux-amd64"
    );
    assert_eq!(
        installer_asset_name("darwin", Architecture::Arm64),
        "dioramactl-darwin-arm64"
    );
}

// -----------------------------------------------------------------------------
// 2. Shell completion generation
// -----------------------------------------------------------------------------

#[test]
fn test_shell_parser() {
    assert_eq!(parse_shell("bash"), Some(Shell::Bash));
    assert_eq!(parse_shell("BASH"), Some(Shell::Bash));
    assert_eq!(parse_shell("zsh"), Some(Shell::Zsh));
    assert_eq!(parse_shell("fish"), Some(Shell::Fish));
    assert_eq!(parse_shell("powershell"), Some(Shell::PowerShell));
    assert_eq!(parse_shell("pwsh"), Some(Shell::PowerShell));
    assert_eq!(parse_shell("unknown"), None);
}

#[test]
fn test_completion_generation_for_all_shells() {
    let shells = [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::PowerShell];
    for shell in shells {
        let mut out = Vec::new();
        dioramactl::generate_completion(shell, &mut out).unwrap();
        let script = String::from_utf8(out).unwrap();
        assert_ne!(script, "");
        assert!(script.contains("dioramactl"));
        assert!(script.contains("check"));
        assert!(script.contains("download"));
        assert!(script.contains("install"));
    }
}

#[test]
fn test_execute_completion_cli() {
    let mut inputs = TestInputs::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    // Valid shell
    let code = execute(
        &args(&["completion", "bash"]),
        &BTreeMap::new(),
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert!(String::from_utf8_lossy(&stdout).contains("_dioramactl"));

    // Missing shell argument
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&["completion"]),
        &BTreeMap::new(),
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&stderr).contains("accepts 1 arg(s), received 0"));

    // Unsupported shell argument
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&["completion", "csh"]),
        &BTreeMap::new(),
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&stderr).contains("unsupported shell: csh"));
}

// -----------------------------------------------------------------------------
// 3. Download workflow execution
// -----------------------------------------------------------------------------

#[test]
fn test_execute_download_success() {
    let mut inputs = TestInputs {
        arch: "aarch64".into(),
        libc: Libc::Musl,
        ..TestInputs::default()
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let download_opts = DownloadOptions {
        version: "v1.1.8".into(),
        path: PathBuf::from("/tmp/diorama-download-test"),
        arch: Some("arm64-musl".into()),
        custom_url: Some("https://example.com/custom.tar.gz".into()),
        temp_dir: Some(PathBuf::from("/tmp/scratch")),
        proxy: Some("http://proxy.internal:8080".into()),
        offline: true,
        libc: None,
    };

    let code = execute_download(&download_opts, &mut inputs, &mut stdout, &mut stderr).unwrap();
    assert_eq!(code, 0);

    assert_eq!(
        inputs.download_url_called.as_deref(),
        Some("https://example.com/custom.tar.gz")
    );
    assert_eq!(
        inputs.download_dest_called.as_ref(),
        Some(&PathBuf::from(
            "/tmp/diorama-download-test/diorama-v1.1.8-linux-arm64-musl-offline.tar.gz"
        ))
    );
    assert_eq!(
        inputs.download_proxy_called.as_deref(),
        Some("http://proxy.internal:8080")
    );
    assert_eq!(
        inputs.copy_self_dest_called.as_ref(),
        Some(&PathBuf::from("/tmp/diorama-download-test/dioramactl"))
    );

    let err_str = String::from_utf8_lossy(&stderr);
    assert!(err_str.contains("Target resolved: diorama-v1.1.8-linux-arm64-musl-offline.tar.gz"));
    assert!(err_str.contains("Bundle ready in /tmp/diorama-download-test"));
    assert_eq!(
        inputs.download_temp_dir_called,
        Some(PathBuf::from("/tmp/scratch"))
    );
    assert!(err_str.contains("--offline-install=./diorama-v1.1.8-linux-arm64-musl-offline.tar.gz"));
}

#[test]
fn mismatched_installer_libc_is_rejected_before_bundle_writes() {
    for (executable_libc, selected_libc) in [(Libc::Glibc, Libc::Musl), (Libc::Musl, Libc::Glibc)] {
        let mut inputs = TestInputs {
            libc: executable_libc,
            ..Default::default()
        };
        let options = DownloadOptions {
            libc: Some(selected_libc),
            ..Default::default()
        };
        assert_eq!(
            execute_download(&options, &mut inputs, &mut Vec::new(), &mut Vec::new()).unwrap(),
            1
        );
        assert!(inputs.download_dest_called.is_none());
        assert!(inputs.copy_self_dest_called.is_none());
    }
}

#[test]
fn test_execute_download_failures() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    // 1. Download file fails
    let mut inputs_fail_download = TestInputs {
        download_fails: true,
        ..Default::default()
    };
    let opts = DownloadOptions {
        version: "v1.1.8".into(),
        path: PathBuf::from("/tmp"),
        arch: Some("amd64".into()),
        custom_url: None,
        temp_dir: None,
        proxy: None,
        offline: false,
        libc: None,
    };
    let code =
        execute_download(&opts, &mut inputs_fail_download, &mut stdout, &mut stderr).unwrap();
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&stderr).contains("[fail] download: mock download failure"));

    // 2. Copy self fails
    stderr.clear();
    let mut inputs_fail_copy = TestInputs {
        copy_self_fails: true,
        ..Default::default()
    };
    let code = execute_download(&opts, &mut inputs_fail_copy, &mut stdout, &mut stderr).unwrap();
    assert_eq!(code, 1);
    assert!(
        String::from_utf8_lossy(&stderr).contains("[fail] copy installer: mock copy_self failure")
    );
}

// -----------------------------------------------------------------------------
// 4. Sudo environment recovery & secret redaction
// -----------------------------------------------------------------------------

#[test]
fn test_recover_sudo_env_from_bytes() {
    let mut env = BTreeMap::new();
    let raw_bytes = b"PATH=/usr/bin\x00SUDO_USER=alice\x00KUBESOLO_VERSION=v1.2.0\x00KUBESOLO_PORTAINER_EDGE_KEY=secret_key_abc\x00OTHER=ignored\x00";

    // Scenario A: Not running under sudo -> ignored
    recover_sudo_env_from_bytes(&mut env, raw_bytes);
    assert!(env.is_empty());

    // Scenario B: Running under sudo (SUDO_USER present), edge key missing in env -> recovered
    env.insert("SUDO_USER".into(), "alice".into());
    recover_sudo_env_from_bytes(&mut env, raw_bytes);
    assert!(!env.contains_key("KUBESOLO_VERSION"));
    assert_eq!(
        env.get("KUBESOLO_PORTAINER_EDGE_KEY").map(String::as_str),
        Some("secret_key_abc")
    );
    assert!(!env.contains_key("OTHER"));
    assert!(!env.contains_key("PATH"));

    // Scenario C: Edge key already present in environment -> does nothing
    let mut env2 = BTreeMap::new();
    env2.insert("SUDO_USER".into(), "bob".into());
    env2.insert("KUBESOLO_PORTAINER_EDGE_KEY".into(), "existing_key".into());
    recover_sudo_env_from_bytes(&mut env2, raw_bytes);
    assert_eq!(
        env2.get("KUBESOLO_PORTAINER_EDGE_KEY").map(String::as_str),
        Some("existing_key")
    );
    assert!(!env2.contains_key("KUBESOLO_VERSION"));
}

#[test]
fn test_install_options_debug_redaction() {
    let opts = InstallOptions {
        portainer_edge_key: Some("super_secret_edge_credential_xyz".into()),
        portainer_edge_id: Some("edge-id-123".into()),
        ..Default::default()
    };

    let debug_repr = format!("{opts:?}");
    assert!(!debug_repr.contains("super_secret_edge_credential_xyz"));
    assert!(debug_repr.contains("<redacted>"));
    assert!(debug_repr.contains("edge-id-123"));
}

// -----------------------------------------------------------------------------
// 5. CommandHandler dispatch and DefaultCommandHandler
// -----------------------------------------------------------------------------

#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct MockCommandHandler {
    check_called: bool,
    completion_called: bool,
    download_called: bool,
    install_called: bool,
    uninstall_called: bool,
    upgrade_called: bool,
    reset_called: bool,
    config_called: bool,
    kubeconfig_called: bool,
    d2k_called: bool,
}

impl CommandHandler for MockCommandHandler {
    fn execute_check(
        &mut self,
        _options: CheckOptions,
        _inputs: &mut dyn CheckInputs,
        _stderr: &mut dyn Write,
    ) -> io::Result<u8> {
        self.check_called = true;
        Ok(42)
    }
    fn execute_completion(
        &mut self,
        _options: CompletionOptions,
        _stdout: &mut dyn Write,
        _stderr: &mut dyn Write,
    ) -> io::Result<u8> {
        self.completion_called = true;
        Ok(43)
    }
    fn execute_download(
        &mut self,
        _options: DownloadOptions,
        _inputs: &mut dyn CheckInputs,
        _stdout: &mut dyn Write,
        _stderr: &mut dyn Write,
    ) -> io::Result<u8> {
        self.download_called = true;
        Ok(44)
    }
    fn execute_install(
        &mut self,
        _options: InstallOptions,
        _inputs: &mut dyn CheckInputs,
        _stdout: &mut dyn Write,
        _stderr: &mut dyn Write,
    ) -> io::Result<u8> {
        self.install_called = true;
        Ok(45)
    }
    fn execute_uninstall(
        &mut self,
        _options: UninstallOptions,
        _inputs: &mut dyn CheckInputs,
        _stdout: &mut dyn Write,
        _stderr: &mut dyn Write,
    ) -> io::Result<u8> {
        self.uninstall_called = true;
        Ok(46)
    }
    fn execute_upgrade(
        &mut self,
        _options: UpgradeOptions,
        _inputs: &mut dyn CheckInputs,
        _stdout: &mut dyn Write,
        _stderr: &mut dyn Write,
    ) -> io::Result<u8> {
        self.upgrade_called = true;
        Ok(47)
    }
    fn execute_reset(
        &mut self,
        _options: ResetOptions,
        _inputs: &mut dyn CheckInputs,
        _stdout: &mut dyn Write,
        _stderr: &mut dyn Write,
    ) -> io::Result<u8> {
        self.reset_called = true;
        Ok(48)
    }
    fn execute_config(
        &mut self,
        _options: ConfigOptions,
        _inputs: &mut dyn CheckInputs,
        _stdout: &mut dyn Write,
        _stderr: &mut dyn Write,
    ) -> io::Result<u8> {
        self.config_called = true;
        Ok(49)
    }
    fn execute_kubeconfig(
        &mut self,
        _options: KubeconfigOptions,
        _inputs: &mut dyn CheckInputs,
        _stdout: &mut dyn Write,
        _stderr: &mut dyn Write,
    ) -> io::Result<u8> {
        self.kubeconfig_called = true;
        Ok(50)
    }
    fn execute_d2k(
        &mut self,
        _options: D2kOptions,
        _inputs: &mut dyn CheckInputs,
        _stdout: &mut dyn Write,
        _stderr: &mut dyn Write,
    ) -> io::Result<u8> {
        self.d2k_called = true;
        Ok(51)
    }
}

#[test]
fn test_command_handler_dispatch() {
    let mut inputs = TestInputs::default();
    let env = BTreeMap::new();

    let cases = [
        ("check", 42),
        ("completion", 43),
        ("download", 44),
        ("install", 45),
        ("uninstall", 46),
        ("upgrade", 47),
        ("reset", 48),
        ("config", 49),
        ("kubeconfig", 50),
        ("d2k", 51),
    ];

    for (cmd, expected_code) in cases {
        let mut handler = MockCommandHandler::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = execute_with_handler(
            &args(&[cmd]),
            &env,
            "v0.1.0",
            &mut inputs,
            &mut handler,
            &mut stdout,
            &mut stderr,
        )
        .unwrap();

        assert_eq!(code, expected_code, "command {cmd} failed dispatch");
    }
}

#[test]
fn test_default_command_handler_unimplemented_stubs() {
    let mut inputs = TestInputs::default();
    let env = BTreeMap::new();

    // Verify DefaultCommandHandler method directly
    let mut default_handler = DefaultCommandHandler;
    let mut test_stdout = Vec::new();
    let mut test_stderr = Vec::new();
    let direct_code = default_handler
        .execute_install(
            InstallOptions::default(),
            &mut inputs,
            &mut test_stdout,
            &mut test_stderr,
        )
        .unwrap();
    assert_eq!(direct_code, 1);
    assert!(
        String::from_utf8_lossy(&test_stderr).contains("command 'install' is not yet implemented")
    );

    let unimplemented_cmds = ["install"];

    for cmd in unimplemented_cmds {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = execute(
            &args(&[cmd]),
            &env,
            "v0.1.0",
            &mut inputs,
            &mut stdout,
            &mut stderr,
        )
        .unwrap();

        assert_eq!(code, 1, "command {cmd} should exit with code 1");
        let err_msg = String::from_utf8_lossy(&stderr);
        assert!(
            err_msg.contains(&format!("command '{cmd}' is not yet implemented")),
            "error message for {cmd} was: {err_msg}"
        );
    }
}

#[test]
fn test_help_and_version_execution() {
    let mut inputs = TestInputs::default();
    let env = BTreeMap::new();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    // --help
    let code = execute(
        &args(&["--help"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert!(String::from_utf8_lossy(&stdout).contains("diorama Kube management commands"));

    // version
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&["version"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout), "dioramactl v0.1.0\n");

    // subcommand help
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&["install", "--help"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert!(
        String::from_utf8_lossy(&stdout)
            .contains("Install diorama and configure the system service")
    );
}

// -----------------------------------------------------------------------------
// 6. Flag parsing styles & error conditions
// -----------------------------------------------------------------------------

#[test]
fn test_flag_parsing_styles() {
    let env = BTreeMap::new();

    // Flag with '=' style
    let cmd = parse_command(&args(&["download", "--arch=arm64", "--offline=true"]), &env).unwrap();
    if let Command::Download(opts) = cmd {
        assert_eq!(opts.arch.as_deref(), Some("arm64"));
        assert!(opts.offline);
    } else {
        panic!("expected Download command");
    }

    // Flag with space separated value style
    let cmd2 = parse_command(
        &args(&["download", "--arch", "arm64", "--path", "/data"]),
        &env,
    )
    .unwrap();
    if let Command::Download(opts) = cmd2 {
        assert_eq!(opts.arch.as_deref(), Some("arm64"));
        assert_eq!(opts.path, PathBuf::from("/data"));
    } else {
        panic!("expected Download command");
    }

    // Boolean flag with no attached value (defaults to true)
    let cmd3 = parse_command(&args(&["download", "--offline", "--musl"]), &env).unwrap();
    if let Command::Download(opts) = cmd3 {
        assert!(opts.offline);
        assert_eq!(opts.libc, Some(Libc::Musl));
    } else {
        panic!("expected Download command");
    }

    // Unknown flag
    let err = parse_command(&args(&["download", "--nonexistent"]), &env).unwrap_err();
    assert_eq!(err, ParseError::UnknownFlag);

    // Invalid boolean flag value
    let err_bool = parse_command(&args(&["download", "--offline=maybe"]), &env).unwrap_err();
    assert_eq!(err_bool, ParseError::InvalidBoolean);

    // Unknown command
    let err_cmd = parse_command(&args(&["not-a-command"]), &env).unwrap_err();
    assert_eq!(err_cmd, ParseError::UnknownCommand);
}

#[test]
fn mismatched_bundle_installer_is_rejected_before_any_output() {
    for (os, arch, target) in [
        ("darwin", "aarch64", "amd64"),
        ("darwin", "aarch64", "arm64"),
        ("linux", "x86_64", "arm64"),
        ("linux", "aarch64", "amd64"),
        ("linux", "x86_64", "arm"),
        ("linux", "x86_64", "riscv64"),
    ] {
        let mut inputs = TestInputs {
            os: os.into(),
            arch: arch.into(),
            ..TestInputs::default()
        };
        let opts = DownloadOptions {
            arch: Some(target.into()),
            offline: true,
            ..DownloadOptions::default()
        };
        let mut stderr = Vec::new();
        assert_eq!(
            execute_download(&opts, &mut inputs, &mut Vec::new(), &mut stderr).unwrap(),
            1
        );
        assert!(inputs.download_url_called.is_none());
        assert!(inputs.download_dest_called.is_none());
        assert!(inputs.copy_self_dest_called.is_none());
        assert!(!String::from_utf8_lossy(&stderr).contains("Bundle ready"));
    }
}
struct FakeEngine {
    output: io::Result<String>,
    calls: Vec<(String, u16)>,
}

impl dioramactl::endpoints::EnginePortInspector for FakeEngine {
    fn inspect_port(&mut self, container: &str, port: u16) -> io::Result<String> {
        self.calls.push((container.to_string(), port));
        match &self.output {
            Ok(s) => Ok(s.clone()),
            Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
        }
    }
}

const ENDPOINT_KUBECONFIG: &str = "apiVersion: v1\nkind: Config\ncurrent-context: dev\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n  name: dev\n- cluster:\n    server: https://other:6443\n  name: other\ncontexts:\n- context:\n    cluster: dev\n    user: dev\n  name: dev\n- context:\n    cluster: other\n    user: other\n  name: other\nusers:\n- name: dev\n  user:\n    token: a\n- name: other\n  user:\n    token: b\n";

fn endpoint_fixture() -> (tempfile::TempDir, PathBuf, BTreeMap<String, String>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    std::fs::write(&path, ENDPOINT_KUBECONFIG).unwrap();
    let env = BTreeMap::from([("HOME".to_string(), dir.path().display().to_string())]);
    (dir, path, env)
}

fn endpoint_opts(sub: &str, name: Option<&str>, path: &Path) -> KubeconfigOptions {
    KubeconfigOptions {
        subcommand: Some(sub.into()),
        output: Some(path.to_path_buf()),
        name: name.map(Into::into),
        ..KubeconfigOptions::default()
    }
}

#[test]
fn kubeconfig_route_and_remove_flags_parse() {
    let parsed = parse_command(
        &args(&["kubeconfig", "route", "--name", "dev"]),
        &BTreeMap::new(),
    )
    .unwrap();
    let Command::Kubeconfig(o) = parsed else {
        panic!("not kubeconfig")
    };
    assert_eq!(o.subcommand.as_deref(), Some("route"));
    assert_eq!(o.name.as_deref(), Some("dev"));
}

#[test]
fn kubeconfig_route_uses_fake_engine_and_only_changes_selected_server() {
    let (_dir, path, env) = endpoint_fixture();
    let mut engine = FakeEngine {
        output: Ok("0.0.0.0:49153\n[::]:49153\n".into()),
        calls: vec![],
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = dioramactl::kubeconfig::execute_kubeconfig_with_engine(
        &endpoint_opts("route", Some("dev"), &path),
        &mut TestInputs::default(),
        &mut engine,
        &env,
        &mut out,
        &mut err,
    )
    .unwrap();
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    assert_eq!(engine.calls, vec![("dev".to_string(), 6443)]);
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("https://127.0.0.1:49153"));
    assert!(written.contains("https://other:6443"));
    assert!(!written.contains("10.0.0.1"));
}

#[test]
fn kubeconfig_route_reports_engine_and_port_failures_without_writing() {
    for output in [
        Err(io::Error::other("engine down")),
        Ok("no ports".to_string()),
    ] {
        let (_dir, path, env) = endpoint_fixture();
        let mut engine = FakeEngine {
            output,
            calls: vec![],
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = dioramactl::kubeconfig::execute_kubeconfig_with_engine(
            &endpoint_opts("route", Some("dev"), &path),
            &mut TestInputs::default(),
            &mut engine,
            &env,
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(code, 1);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ENDPOINT_KUBECONFIG);
    }
}

#[test]
fn kubeconfig_remove_is_selective_and_requires_name() {
    let (_dir, path, env) = endpoint_fixture();
    let mut engine = FakeEngine {
        output: Ok(String::new()),
        calls: vec![],
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = dioramactl::kubeconfig::execute_kubeconfig_with_engine(
        &endpoint_opts("remove", Some("dev"), &path),
        &mut TestInputs::default(),
        &mut engine,
        &env,
        &mut out,
        &mut err,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(engine.calls, <[(std::string::String, u16); 0]>::default());
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(!written.contains("name: dev") && !written.contains("\"name\": \"dev\""));
    assert!(written.contains("name: other") || written.contains("\"name\": \"other\""));
    assert!(
        !written.contains("current-context: dev")
            && !written.contains("\"current-context\": \"dev\"")
    );

    let code = dioramactl::kubeconfig::execute_kubeconfig_with_engine(
        &endpoint_opts("remove", None, &path),
        &mut TestInputs::default(),
        &mut engine,
        &env,
        &mut out,
        &mut err,
    )
    .unwrap();
    assert_eq!(code, 1);
    let code = dioramactl::kubeconfig::execute_kubeconfig_with_engine(
        &endpoint_opts("remove", Some("missing"), &path),
        &mut TestInputs::default(),
        &mut engine,
        &env,
        &mut out,
        &mut err,
    )
    .unwrap();
    assert_eq!(code, 1);
}

#[test]
fn upgrade_recovery_cli_does_not_prepare_or_download_an_artifact() {
    let root = tempfile::tempdir().unwrap();
    // A completed receipt needs no backend mutation. The recorded spec selects
    // container mode but Docker is never invoked for receipt-only cleanup.
    std::fs::write(
        root.path().join("container.spec"),
        "name=diorama\nimage=example/diorama:v1.3.0\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join(".upgrade-completed"),
        "from=v1.2.0\ntarget=v1.3.0\nbackup=/unused\n",
    )
    .unwrap();
    let mut inputs = TestInputs::default();
    let result = execute(
        &args(&[
            "upgrade",
            "--recover",
            "--path",
            root.path().to_str().unwrap(),
        ]),
        &BTreeMap::new(),
        "v1.3.0",
        &mut inputs,
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(result, 0);
    assert!(inputs.download_url_called.is_none());
    assert!(!root.path().join(".upgrade-completed").exists());
}
