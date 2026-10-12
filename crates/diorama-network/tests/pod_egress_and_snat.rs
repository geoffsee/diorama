use std::fs;
use tempfile::tempdir;

use diorama_network::{
    CommandExecutor, CommandOutput, DEFAULT_NFT_MASQ_TABLE, DEFAULT_POD_CIDR, EgressDecision,
    MASQUERADE_COMMENT, MasqueradeBackend, MockCommandExecutor,
    clean_pod_masquerade_with_backend_and_executor, detect_backend, disable_ipv6_sysctls_in_root,
    ensure_ip_forward_in_root, ensure_pod_masquerade_with_backend_and_executor,
    evaluate_egress_traffic, ipv4_in_cidr, prepare_node_network,
};

#[test]
fn test_ipv4_in_cidr_helper_and_default_cidr() {
    assert_eq!(DEFAULT_POD_CIDR, "10.42.0.0/16");
    assert!(ipv4_in_cidr("10.42.0.1", DEFAULT_POD_CIDR));
    assert!(ipv4_in_cidr("10.42.255.254", DEFAULT_POD_CIDR));
    assert!(!ipv4_in_cidr("10.43.0.1", DEFAULT_POD_CIDR));
    assert!(!ipv4_in_cidr("1.1.1.1", DEFAULT_POD_CIDR));
    assert!(!ipv4_in_cidr("invalid-ip", DEFAULT_POD_CIDR));
    assert!(!ipv4_in_cidr("10.42.0.1", "invalid-cidr"));
}

#[test]
fn test_persisted_pod_restart_proves_snat_readiness_precedes_reconciliation() {
    let dir = tempdir().expect("tempdir");
    let sysctl_root = dir.path().join("proc/sys");
    fs::create_dir_all(sysctl_root.join("net/ipv4")).expect("create sysctl dir");
    fs::write(sysctl_root.join("net/ipv4/ip_forward"), b"1\n").expect("write ip_forward");

    // Ordinary iptables host
    fs::create_dir_all(dir.path().join("proc/net")).expect("proc net");
    fs::write(
        dir.path().join("proc/net/ip_tables_names"),
        b"nat\nfilter\n",
    )
    .expect("ip_tables_names");

    let executor = MockCommandExecutor::new_iptables_host();

    // 1. Node networking is prepared BEFORE any persisted pod reconciliation runs
    let report = prepare_node_network(Some("10.42.0.0/16"), false, Some(dir.path()), &executor)
        .expect("prepare node network");

    assert_eq!(report.backend, MasqueradeBackend::IpTables);
    assert!(report.ip_forward_verified);
    assert_eq!(report.pod_cidr, "10.42.0.0/16");
    assert!(executor.has_owned_iptables_masq_rule());

    // 2. Now simulate restarted persisted pod coming online and probing traffic:
    let pod_ip = "10.42.0.15";

    // Egress probe to external internet (1.1.1.1 or cloudflare.com):
    // Must be masqueraded through SNAT so external packets return to the node
    let egress_decision = evaluate_egress_traffic(pod_ip, "1.1.1.1", &report.pod_cidr);
    assert_eq!(
        egress_decision,
        EgressDecision::Masquerade {
            source_ip: pod_ip.to_string(),
            destination_ip: "1.1.1.1".to_string(),
        }
    );

    // Pod-to-pod probe to another in-cluster pod (10.42.1.20):
    // Must NOT be masqueraded so target pod receives authentic source IP
    let pod_to_pod_decision = evaluate_egress_traffic(pod_ip, "10.42.1.20", &report.pod_cidr);
    assert_eq!(
        pod_to_pod_decision,
        EgressDecision::Direct {
            source_ip: pod_ip.to_string(),
            destination_ip: "10.42.1.20".to_string(),
        }
    );
}

#[test]
fn test_pod_to_pod_and_egress_probes_on_ordinary_iptables_hosts() {
    let executor = MockCommandExecutor::new_iptables_host();
    let cidr = "10.42.0.0/16";

    ensure_pod_masquerade_with_backend_and_executor(cidr, MasqueradeBackend::IpTables, &executor)
        .expect("ensure iptables masq");

    assert!(executor.has_owned_iptables_masq_rule());

    // Verify command logged exact required arguments
    let logs = executor.command_log.lock().unwrap();
    assert!(logs.iter().any(|cmd| {
        cmd.contains("-t nat -A POSTROUTING")
            && cmd.contains("-s 10.42.0.0/16 ! -d 10.42.0.0/16")
            && cmd.contains(MASQUERADE_COMMENT)
            && cmd.contains("-j MASQUERADE")
    }));
    drop(logs);

    // Probes
    assert_eq!(
        evaluate_egress_traffic("10.42.0.5", "8.8.8.8", cidr),
        EgressDecision::Masquerade {
            source_ip: "10.42.0.5".to_string(),
            destination_ip: "8.8.8.8".to_string(),
        }
    );

    assert_eq!(
        evaluate_egress_traffic("10.42.0.5", "10.42.0.99", cidr),
        EgressDecision::Direct {
            source_ip: "10.42.0.5".to_string(),
            destination_ip: "10.42.0.99".to_string(),
        }
    );
}

#[test]
fn test_pod_to_pod_and_egress_probes_on_nftables_only_hosts() {
    let executor = MockCommandExecutor::new_nftables_host();
    let cidr = "10.42.0.0/16";

    ensure_pod_masquerade_with_backend_and_executor(cidr, MasqueradeBackend::Nftables, &executor)
        .expect("ensure nftables masq");

    assert!(executor.has_owned_nft_masq_rule());

    // Verify command logged exact required nftables objects
    let logs = executor.command_log.lock().unwrap();
    assert!(
        logs.iter()
            .any(|cmd| cmd.contains(&format!("add table ip {DEFAULT_NFT_MASQ_TABLE}")))
    );
    assert!(logs.iter().any(|cmd| cmd.contains(&format!(
        "add chain ip {DEFAULT_NFT_MASQ_TABLE} postrouting"
    ))));
    assert!(logs.iter().any(|cmd| {
        cmd.contains(&format!("add rule ip {DEFAULT_NFT_MASQ_TABLE} postrouting"))
            && cmd.contains("ip saddr 10.42.0.0/16 ip daddr != 10.42.0.0/16")
            && cmd.contains("masquerade")
    }));
    drop(logs);

    // Probes
    assert_eq!(
        evaluate_egress_traffic("10.42.0.7", "1.1.1.1", cidr),
        EgressDecision::Masquerade {
            source_ip: "10.42.0.7".to_string(),
            destination_ip: "1.1.1.1".to_string(),
        }
    );

    assert_eq!(
        evaluate_egress_traffic("10.42.0.7", "10.42.2.80", cidr),
        EgressDecision::Direct {
            source_ip: "10.42.0.7".to_string(),
            destination_ip: "10.42.2.80".to_string(),
        }
    );
}

#[test]
fn test_already_correct_read_only_sysctls_succeed() {
    let dir = tempdir().expect("tempdir");
    let sysctl_root = dir.path().join("proc/sys");

    // 1. Prepare net.ipv4.ip_forward with "1"
    let ip_forward_path = sysctl_root.join("net/ipv4/ip_forward");
    fs::create_dir_all(ip_forward_path.parent().unwrap()).unwrap();
    fs::write(&ip_forward_path, b"1\n").unwrap();

    // 2. Prepare ipv6 disablement paths with "1"
    let ipv6_paths = [
        sysctl_root.join("net/ipv6/conf/all/disable_ipv6"),
        sysctl_root.join("net/ipv6/conf/default/disable_ipv6"),
        sysctl_root.join("net/ipv6/conf/lo/disable_ipv6"),
    ];
    for p in &ipv6_paths {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"1\n").unwrap();
    }

    // Simulate read-only filesystem by setting read-only file permissions (0444)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&ip_forward_path, fs::Permissions::from_mode(0o444)).unwrap();
        for p in &ipv6_paths {
            fs::set_permissions(p, fs::Permissions::from_mode(0o444)).unwrap();
        }
    }

    // Both operations must succeed without attempting any write!
    assert!(ensure_ip_forward_in_root(&sysctl_root).is_ok());
    assert!(disable_ipv6_sysctls_in_root(&sysctl_root).is_ok());
}

#[test]
fn test_repeated_setup_and_cleanup_neither_duplicates_rules_nor_flushes_unrelated_nat_state() {
    let cidr = "10.42.0.0/16";

    // ── IPTABLES HOST ────────────────────────────────────────────────────────
    let ip_executor = MockCommandExecutor::new_iptables_host();
    let initial_unrelated_iptables = ip_executor.unrelated_nat_rules_count();
    assert_eq!(initial_unrelated_iptables, 1);

    // Call setup 5 times
    for _ in 0..5 {
        ensure_pod_masquerade_with_backend_and_executor(
            cidr,
            MasqueradeBackend::IpTables,
            &ip_executor,
        )
        .expect("iptables setup");
    }

    // Exactly 1 rule added, no duplicates
    assert_eq!(ip_executor.owned_iptables_rule_count(), 1);
    assert_eq!(
        ip_executor.unrelated_nat_rules_count(),
        initial_unrelated_iptables
    );

    // Call cleanup 3 times
    for _ in 0..3 {
        clean_pod_masquerade_with_backend_and_executor(
            cidr,
            MasqueradeBackend::IpTables,
            &ip_executor,
        )
        .expect("iptables clean");
    }

    // Owned rule deleted, unrelated NAT state completely preserved
    assert_eq!(ip_executor.owned_iptables_rule_count(), 0);
    assert_eq!(
        ip_executor.unrelated_nat_rules_count(),
        initial_unrelated_iptables
    );

    // ── NFTABLES HOST ────────────────────────────────────────────────────────
    let nft_executor = MockCommandExecutor::new_nftables_host();
    let initial_unrelated_nft = nft_executor.unrelated_nat_rules_count();
    assert_eq!(initial_unrelated_nft, 1);

    // Call setup 5 times
    for _ in 0..5 {
        ensure_pod_masquerade_with_backend_and_executor(
            cidr,
            MasqueradeBackend::Nftables,
            &nft_executor,
        )
        .expect("nftables setup");
    }

    // Exactly 1 rule added, no duplicates
    assert_eq!(nft_executor.owned_nft_rule_count(), 1);
    assert_eq!(
        nft_executor.unrelated_nat_rules_count(),
        initial_unrelated_nft
    );

    // Call cleanup 3 times
    for _ in 0..3 {
        clean_pod_masquerade_with_backend_and_executor(
            cidr,
            MasqueradeBackend::Nftables,
            &nft_executor,
        )
        .expect("nftables clean");
    }

    // Owned rule deleted, unrelated NAT state (table ip nat) completely preserved
    assert_eq!(nft_executor.owned_nft_rule_count(), 0);
    assert_eq!(
        nft_executor.unrelated_nat_rules_count(),
        initial_unrelated_nft
    );
}

#[test]
fn test_unsupported_host_detection_fails_actionably() {
    struct EmptyExecutor;
    impl CommandExecutor for EmptyExecutor {
        fn run(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput, std::io::Error> {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "command not found",
            ))
        }
    }

    let dir = tempdir().expect("tempdir");
    let err = detect_backend(Some(dir.path()), &EmptyExecutor).unwrap_err();

    assert_eq!(err.diagnostic_code(), "network-masquerade-error");
    assert!(err.to_string().contains("neither iptables"));
}

#[test]
fn test_iptables_and_nftables_cleanup_unexpected_errors_are_reported() {
    struct FailingExecutor {
        stderr: String,
    }
    impl CommandExecutor for FailingExecutor {
        fn run(&self, _program: &str, _args: &[&str]) -> Result<CommandOutput, std::io::Error> {
            Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: self.stderr.clone(),
            })
        }
    }

    // iptables lock timeout or permission error:
    let fail_iptables = FailingExecutor {
        stderr: "iptables: Resource temporarily unavailable (xtables lock timeout)\n".to_string(),
    };
    let err_iptables = clean_pod_masquerade_with_backend_and_executor(
        "10.42.0.0/16",
        MasqueradeBackend::IpTables,
        &fail_iptables,
    )
    .unwrap_err();
    assert_eq!(err_iptables.diagnostic_code(), "network-masquerade-error");
    assert!(err_iptables.to_string().contains("xtables lock timeout"));

    // nftables unexpected error (e.g. Operation not permitted):
    let fail_nft = FailingExecutor {
        stderr: "Error: Could not process rule: Operation not permitted\n".to_string(),
    };
    let err_nft = clean_pod_masquerade_with_backend_and_executor(
        "10.42.0.0/16",
        MasqueradeBackend::Nftables,
        &fail_nft,
    )
    .unwrap_err();
    assert_eq!(err_nft.diagnostic_code(), "network-masquerade-error");
    assert!(err_nft.to_string().contains("Operation not permitted"));
}

#[test]
fn test_nftables_idempotency_detects_cidr_change() {
    let executor = MockCommandExecutor::new_nftables_host();
    let old_cidr = "10.42.0.0/16";
    let new_cidr = "10.43.0.0/16";

    // Establish old CIDR
    ensure_pod_masquerade_with_backend_and_executor(
        old_cidr,
        MasqueradeBackend::Nftables,
        &executor,
    )
    .expect("setup old cidr");
    assert_eq!(executor.owned_nft_rule_count(), 1);

    // Call setup again with NEW CIDR: must add the new rule and not falsely skip
    ensure_pod_masquerade_with_backend_and_executor(
        new_cidr,
        MasqueradeBackend::Nftables,
        &executor,
    )
    .expect("setup new cidr");

    let rules = executor.nft_rules.lock().unwrap();
    assert!(rules.iter().any(|r| r.contains("10.43.0.0/16")));
}
