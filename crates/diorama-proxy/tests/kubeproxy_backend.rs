use std::fs;
use std::sync::Arc;

use diorama_network::{CommandExecutor, CommandOutput, MockCommandExecutor};
use diorama_proxy::{
    KubeProxyOptions, ProxyError, ProxyMode, ProxyService, check_sysctl_conntrack_writable,
    detect_proxy_backend, flush_nftables_nat,
};
use tempfile::TempDir;

struct CustomCommandExecutor<F>
where
    F: Fn(&str, &[&str]) -> Result<CommandOutput, std::io::Error> + Send + Sync,
{
    handler: F,
}

impl<F> CustomCommandExecutor<F>
where
    F: Fn(&str, &[&str]) -> Result<CommandOutput, std::io::Error> + Send + Sync,
{
    fn new(handler: F) -> Self {
        Self { handler }
    }
}

impl<F> CommandExecutor for CustomCommandExecutor<F>
where
    F: Fn(&str, &[&str]) -> Result<CommandOutput, std::io::Error> + Send + Sync,
{
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, std::io::Error> {
        (self.handler)(program, args)
    }
}

#[test]
fn test_detect_backend_iptables_available() {
    let temp = TempDir::new().unwrap();
    let proc_net = temp.path().join("proc/net");
    fs::create_dir_all(&proc_net).unwrap();
    fs::write(proc_net.join("ip_tables_names"), "filter\nnat\nmangle\n").unwrap();

    let mock = MockCommandExecutor::new_iptables_host();
    let mode = detect_proxy_backend(Some(temp.path()), &mock).unwrap();
    assert_eq!(mode, ProxyMode::IpTables);
}

#[test]
fn test_detect_backend_nftables_only() {
    let temp = TempDir::new().unwrap();
    // No /proc/net/ip_tables_names exists (nftables-only system)
    let mock = MockCommandExecutor::new_nftables_host();
    let mode = detect_proxy_backend(Some(temp.path()), &mock).unwrap();
    assert_eq!(mode, ProxyMode::Nftables);
}

#[test]
fn test_detect_backend_actionable_error_when_iptables_modules_present_but_binary_missing() {
    let temp = TempDir::new().unwrap();
    let proc_net = temp.path().join("proc/net");
    fs::create_dir_all(&proc_net).unwrap();
    fs::write(proc_net.join("ip_tables_names"), "filter\nnat\n").unwrap();

    // iptables fails (binary not in PATH or missing)
    let custom = CustomCommandExecutor::new(|program, _| {
        if program == "iptables" {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "iptables: command not found",
            ))
        } else {
            Ok(CommandOutput::default())
        }
    });

    let err = detect_proxy_backend(Some(temp.path()), &custom).unwrap_err();
    match err {
        ProxyError::UnsupportedCapability {
            reason,
            recommendation,
        } => {
            assert!(
                reason.contains(
                    "/proc/net/ip_tables_names is present but iptables binary is unavailable"
                ),
                "reason should identify iptables binary unavailability: {reason}"
            );
            assert!(
                recommendation.contains("install the iptables package"),
                "recommendation should guide operator: {recommendation}"
            );
        },
        other => panic!("expected UnsupportedCapability error, got: {other:?}"),
    }
}

#[test]
fn test_detect_backend_actionable_error_when_neither_iptables_nor_nftables_available() {
    let temp = TempDir::new().unwrap();
    // Neither /proc/net/ip_tables_names nor nft binary is available
    let mock = MockCommandExecutor::default();

    let err = detect_proxy_backend(Some(temp.path()), &mock).unwrap_err();
    match err {
        ProxyError::UnsupportedCapability {
            reason,
            recommendation,
        } => {
            assert!(
                reason.contains(
                    "neither iptables (/proc/net/ip_tables_names) nor nftables (nft) is available"
                ),
                "reason should state neither backend is available: {reason}"
            );
            assert!(
                recommendation.contains("install iptables or nftables kernel modules"),
                "recommendation should guide operator: {recommendation}"
            );
        },
        other => panic!("expected UnsupportedCapability error, got: {other:?}"),
    }
}

#[test]
fn test_flush_nftables_nat_table_success_and_benign_missing_table() {
    // 1. Successful flush with MockCommandExecutor
    let mock = MockCommandExecutor::new_nftables_host();
    assert!(flush_nftables_nat(&mock).is_ok());

    // 2. Table does not exist (benign)
    let custom_missing = CustomCommandExecutor::new(|program, args| {
        if program == "nft" && args.first() == Some(&"flush") {
            Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "Error: No such file or directory; did you mean table 'filter' in family ip?\nflush table ip nat".to_string(),
            })
        } else {
            Ok(CommandOutput::default())
        }
    });
    assert!(flush_nftables_nat(&custom_missing).is_ok());

    // 3. Non-benign failure (e.g. Permission denied) returns CommandExecutionFailed error
    let custom_fail = CustomCommandExecutor::new(|program, args| {
        if program == "nft" && args.first() == Some(&"flush") {
            Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "Error: Permission denied (you must be root)\n".to_string(),
            })
        } else {
            Ok(CommandOutput::default())
        }
    });
    let err = flush_nftables_nat(&custom_fail).unwrap_err();
    match err {
        ProxyError::CommandExecutionFailed { command, reason } => {
            assert!(command.contains("nft flush table ip nat"));
            assert!(reason.contains("Permission denied"));
        },
        other => panic!("expected CommandExecutionFailed error, got: {other:?}"),
    }
}

#[test]
fn test_readonly_proc_sys_container_mode_starts_successfully() {
    let temp = TempDir::new().unwrap();
    let netfilter = temp.path().join("proc/sys/net/netfilter");
    fs::create_dir_all(&netfilter).unwrap();
    let conntrack_max = netfilter.join("nf_conntrack_max");
    fs::write(&conntrack_max, "131072\n").unwrap();

    // Mark file readonly
    let mut perms = fs::metadata(&conntrack_max).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&conntrack_max, perms).unwrap();

    // In container mode (container_mode = true), conntrack tuning is disabled (zeroed),
    // so read-only /proc/sys succeeds without trying to write to the kernel.
    let result = check_sysctl_conntrack_writable(Some(temp.path()), true);
    assert!(result.is_ok());
}

#[test]
fn test_readonly_proc_sys_host_mode_gives_actionable_error() {
    let temp = TempDir::new().unwrap();
    let netfilter = temp.path().join("proc/sys/net/netfilter");
    fs::create_dir_all(&netfilter).unwrap();
    let conntrack_max = netfilter.join("nf_conntrack_max");
    fs::write(&conntrack_max, "131072\n").unwrap();

    // Mark file readonly
    let mut perms = fs::metadata(&conntrack_max).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&conntrack_max, perms).unwrap();

    // In host mode (container_mode = false), read-only /proc/sys gives an actionable error
    // instructing the operator to enable container mode!
    let err = check_sysctl_conntrack_writable(Some(temp.path()), false).unwrap_err();
    match err {
        ProxyError::ReadOnlySysctl { path, reason } => {
            assert_eq!(path, conntrack_max);
            assert!(
                reason.contains("permission denied") || reason.contains("read-only"),
                "reason should report permission or readonly: {reason}"
            );
        },
        other => panic!("expected ReadOnlySysctl error, got: {other:?}"),
    }
}

#[test]
fn test_nftables_only_service_full_prerequisites_and_startup() {
    let temp = TempDir::new().unwrap();
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let mock = MockCommandExecutor::new_nftables_host();
    let options = KubeProxyOptions::new(
        kubeconfig,
        true, // container_mode = true
        ProxyMode::Nftables,
    );

    let mut service = ProxyService::new(options)
        .with_executor(Arc::new(mock))
        .with_sys_root(temp.path().to_path_buf());

    assert!(service.check_prerequisites().is_ok());
    assert_eq!(service.options().proxy_mode, ProxyMode::Nftables);

    assert!(service.start().is_ok());
    assert!(service.is_running());

    let health = service.check_readiness().unwrap();
    assert!(health.is_healthy);
    assert_eq!(health.proxy_mode, ProxyMode::Nftables);
    assert!(health.container_mode);
    assert!(health.all_conntrack_zero);
    assert!(service.is_ready());

    service.stop();
    assert!(!service.is_running());
    assert!(!service.is_ready());
}

#[test]
fn test_check_readiness_masquerade_failure_propagates_error() {
    let temp = TempDir::new().unwrap();
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let proc_net = temp.path().join("proc/net");
    fs::create_dir_all(&proc_net).unwrap();
    fs::write(proc_net.join("ip_tables_names"), "filter\nnat\n").unwrap();

    let custom_fail = CustomCommandExecutor::new(|program, args| {
        if program == "iptables" && args.contains(&"--version") {
            Ok(CommandOutput {
                success: true,
                stdout: "iptables v1.8.10".to_string(),
                stderr: String::new(),
            })
        } else if program == "iptables" && args.contains(&"POSTROUTING") {
            // Fails masquerade rule check and addition
            Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "iptables: Permission denied (you must be root)".to_string(),
            })
        } else {
            Ok(CommandOutput::default())
        }
    });

    let options = KubeProxyOptions::new(kubeconfig, true, ProxyMode::IpTables);

    let mut service = ProxyService::new(options)
        .with_executor(Arc::new(custom_fail))
        .with_sys_root(temp.path().to_path_buf());

    assert!(service.check_prerequisites().is_ok());
    assert!(service.start().is_ok());
    assert!(service.is_running());

    // Masquerade fails -> check_readiness returns Err(ProxyError::MasqueradeFailed)
    let err = service.check_readiness().unwrap_err();
    match err {
        ProxyError::MasqueradeFailed { reason } => {
            assert!(
                reason.contains("Permission denied") || reason.contains("failed"),
                "reason should report masquerade failure: {reason}"
            );
        },
        other => panic!("expected MasqueradeFailed error, got: {other:?}"),
    }

    assert!(!service.is_ready());
    assert!(!service.is_snat_ready());
}

#[test]
fn test_check_readiness_failure_resets_ready_and_snat_flags() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let temp = TempDir::new().unwrap();
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let proc_net = temp.path().join("proc/net");
    fs::create_dir_all(&proc_net).unwrap();
    fs::write(proc_net.join("ip_tables_names"), "filter\nnat\n").unwrap();

    let should_fail = Arc::new(AtomicBool::new(false));
    let should_fail_clone = Arc::clone(&should_fail);

    let custom = CustomCommandExecutor::new(move |program, args| {
        if program == "iptables" && args.contains(&"--version") {
            Ok(CommandOutput {
                success: true,
                stdout: "iptables v1.8.10".to_string(),
                stderr: String::new(),
            })
        } else if program == "iptables" && args.contains(&"POSTROUTING") {
            if should_fail_clone.load(Ordering::SeqCst) {
                Ok(CommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "iptables: table flushed or removed".to_string(),
                })
            } else {
                Ok(CommandOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
        } else {
            Ok(CommandOutput::default())
        }
    });

    let options = KubeProxyOptions::new(kubeconfig, true, ProxyMode::IpTables);
    let mut service = ProxyService::new(options)
        .with_executor(Arc::new(custom))
        .with_sys_root(temp.path().to_path_buf());

    assert!(service.check_prerequisites().is_ok());
    assert!(service.start().is_ok());

    // First readiness check succeeds
    let health = service.check_readiness().unwrap();
    assert!(health.is_healthy);
    assert!(service.is_ready());
    assert!(service.is_snat_ready());

    // Trigger failure on next readiness check
    should_fail.store(true, Ordering::SeqCst);
    let err = service.check_readiness().unwrap_err();
    match err {
        ProxyError::MasqueradeFailed { .. } => {},
        other => panic!("expected MasqueradeFailed error, got: {other:?}"),
    }

    // Flags must be reset to false
    assert!(!service.is_ready());
    assert!(!service.is_snat_ready());
}

#[test]
fn test_check_readiness_reports_all_conntrack_zero_when_container_mode_overridden() {
    use diorama_proxy::ConntrackConfiguration;

    let temp = TempDir::new().unwrap();
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let mock = MockCommandExecutor::new_nftables_host();
    let mut options = KubeProxyOptions::new(
        kubeconfig,
        true, // container_mode = true
        ProxyMode::Nftables,
    );
    // Explicitly set non-zero conntrack on options struct
    options.conntrack = ConntrackConfiguration::default_host();
    assert!(!options.conntrack.is_all_zero());

    let mut service = ProxyService::new(options)
        .with_executor(Arc::new(mock))
        .with_sys_root(temp.path().to_path_buf());

    assert!(service.check_prerequisites().is_ok());
    assert!(service.start().is_ok());

    let health = service.check_readiness().unwrap();
    assert!(health.is_healthy);
    assert!(health.container_mode);
    // Even though options.conntrack had non-zero values, effective_conntrack is all zero!
    assert!(health.all_conntrack_zero);
}
