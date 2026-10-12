use diorama_platform::constrained::*;
use diorama_platform::preflight::{CheckStatus, RuntimeOwnership};
use diorama_platform::{Observation, PlatformError, ProbeFailure, ProbeLimits};
fn facts() -> ConstrainedFacts {
    ConstrainedFacts {
        sysctls: std::array::from_fn(|_| Observation::Present("1\n".into())),
        proc_sys_read_only: Observation::Present(false),
        ip_tables_names: Observation::Absent,
        default_cni_plugins: [Observation::Absent; 4],
        cni_config_names: Observation::Present(vec![]),
    }
}
fn inputs() -> ConstrainedInputs {
    ConstrainedInputs {
        runtime: RuntimeOwnership::External,
        iptables_version: Observation::Present("iptables v1.8.10 (nf_tables)".into()),
        xtables_comment: CheckStatus::Blocker,
    }
}
#[test]
fn correct_values_require_no_writes_and_missing_ipv4_is_not_optional() {
    let mut facts = facts();
    let report = evaluate_constrained(&facts, &inputs());
    assert_eq!(report.sysctls, [SysctlState::AlreadyCorrect; 4]);
    facts.sysctls = [
        Observation::Absent,
        Observation::Absent,
        Observation::Present("0\n".into()),
        Observation::Unknown(ProbeFailure::PermissionDenied),
    ];
    assert_eq!(
        evaluate_constrained(&facts, &inputs()).sysctls,
        [
            SysctlState::RequiredAbsent,
            SysctlState::OptionalAbsent,
            SysctlState::NeedsPreparation,
            SysctlState::Unknown(ProbeFailure::PermissionDenied)
        ]
    );
    for invalid in ["", "10", "1garbage", "-1", "2", "1\n0"] {
        facts.sysctls[0] = Observation::Present(invalid.into());
        assert_eq!(
            evaluate_constrained(&facts, &inputs()).sysctls[0],
            SysctlState::Unknown(ProbeFailure::Malformed)
        );
    }
}
#[test]
fn backend_hints_remain_independent_and_never_waive_xtables() {
    let mut facts = facts();
    let mut inputs = inputs();
    let report = evaluate_constrained(&facts, &inputs);
    assert_eq!(
        report.proxy_selection,
        Observation::Present(ProxyBackend::Nftables)
    );
    assert_eq!(
        report.module_family,
        Observation::Present(ModuleFamily::NfTables)
    );
    assert_eq!(report.xtables_comment, CheckStatus::Blocker);
    facts.ip_tables_names = Observation::Present(true);
    assert_eq!(
        evaluate_constrained(&facts, &inputs).proxy_selection,
        Observation::Present(ProxyBackend::Iptables)
    );
    inputs.iptables_version = Observation::Present("iptables (legacy)".into());
    facts.ip_tables_names = Observation::Absent;
    let report = evaluate_constrained(&facts, &inputs);
    assert_eq!(
        report.module_family,
        Observation::Present(ModuleFamily::Legacy)
    );
    assert_eq!(
        report.proxy_selection,
        Observation::Present(ProxyBackend::Nftables)
    );
    facts.ip_tables_names = Observation::Unknown(ProbeFailure::PermissionDenied);
    inputs.iptables_version = Observation::Unknown(ProbeFailure::Io);
    let report = evaluate_constrained(&facts, &inputs);
    assert_eq!(
        report.proxy_selection,
        Observation::Unknown(ProbeFailure::PermissionDenied)
    );
    assert_eq!(report.module_family, Observation::Unknown(ProbeFailure::Io));
}
#[test]
fn external_responsibility_does_not_adopt_host_resources() {
    let mut facts = facts();
    facts.cni_config_names = Observation::Present(vec![
        "00-custom.conflist".into(),
        "20-other.conf".into(),
        "30-other.json".into(),
        OWNED_CNI_CONFIG.into(),
        "00-ignore.txt".into(),
    ]);
    let report = evaluate_constrained(&facts, &inputs());
    assert_eq!(OWNED_CNI_CONFIG, "10-bridge.conflist");
    assert_eq!(CNI_PLUGINS, ["bridge", "host-local", "portmap", "loopback"]);
    assert_eq!(report.responsibilities, RuntimeResponsibilities::External);
    assert_eq!(report.plugins, [PluginState::DefaultLocationMissing; 4]);
    assert_eq!(
        report.cni_ordering,
        Observation::Present(CniOrdering {
            earlier: 1,
            later: 2
        })
    );
    facts.default_cni_plugins[0] = Observation::Unknown(ProbeFailure::PermissionDenied);
    facts.cni_config_names = Observation::Unknown(ProbeFailure::TooLarge);
    let report = evaluate_constrained(&facts, &inputs());
    assert_eq!(
        report.plugins[0],
        PluginState::Unknown(ProbeFailure::PermissionDenied)
    );
    assert_eq!(
        report.cni_ordering,
        Observation::Unknown(ProbeFailure::TooLarge)
    );
}
#[test]
fn collector_never_claims_unsupported_platform_or_invalid_limits() {
    if cfg!(target_os = "linux") {
        let limits = ProbeLimits {
            bytes_per_file: 0,
            ..ProbeLimits::default()
        };
        assert_eq!(
            collect_constrained(limits),
            Err(PlatformError::InvalidLimits)
        );
        let facts = collect_constrained(ProbeLimits::default()).unwrap();
        assert_eq!(facts.sysctls.len(), 4);
        assert_eq!(facts.default_cni_plugins.len(), 4);
    } else {
        assert_eq!(
            collect_constrained(ProbeLimits::default()),
            Err(PlatformError::UnsupportedHost)
        );
    }
}

#[test]
fn read_only_proc_sys_blocks_required_writes_without_changing_correct_values() {
    let mut correct = facts();
    correct.proc_sys_read_only = Observation::Present(true);
    assert_eq!(
        evaluate_constrained(&correct, &inputs()).sysctls,
        [SysctlState::AlreadyCorrect; 4]
    );

    let mut ipv4 = facts();
    ipv4.proc_sys_read_only = Observation::Present(true);
    ipv4.sysctls[0] = Observation::Present("0\n".into());
    assert_eq!(
        evaluate_constrained(&ipv4, &inputs()).sysctls[0],
        SysctlState::ReadOnly
    );

    let mut writable = facts();
    writable.proc_sys_read_only = Observation::Present(false);
    writable.sysctls[0] = Observation::Present("0\n".into());
    assert_eq!(
        evaluate_constrained(&writable, &inputs()).sysctls[0],
        SysctlState::NeedsPreparation
    );

    let mut absent_ipv6 = facts();
    absent_ipv6.proc_sys_read_only = Observation::Present(true);
    absent_ipv6.sysctls[1] = Observation::Absent;
    absent_ipv6.sysctls[2] = Observation::Absent;
    absent_ipv6.sysctls[3] = Observation::Absent;
    assert_eq!(
        &evaluate_constrained(&absent_ipv6, &inputs()).sysctls[1..],
        &[
            SysctlState::OptionalAbsent,
            SysctlState::OptionalAbsent,
            SysctlState::OptionalAbsent
        ]
    );
}
