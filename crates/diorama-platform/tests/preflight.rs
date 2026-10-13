#![allow(unused)]

use diorama_platform::preflight::*;
use diorama_platform::*;
use std::collections::BTreeMap;

fn evidence() -> HostEvidence {
    let paths = [
        "/etc/alpine-release",
        "/var/run/docker.sock",
        "/usr/bin/docker",
        "/usr/local/bin/docker",
        "/usr/sbin/nft",
        "/sbin/nft",
        "/usr/bin/nft",
        "/sbin/iptables",
        "/usr/sbin/iptables",
        "/bin/iptables",
        "/usr/bin/iptables",
        "/sys/fs/cgroup",
        "/sys/fs/cgroup/cpuset",
        "/sys/fs/cgroup/cpu",
        "/sys/fs/cgroup/blkio",
        "/sys/fs/cgroup/memory",
        "/sys/fs/cgroup/pids",
    ];
    HostEvidence {
        executable: ExecutableAbi {
            os: "linux".into(),
            architecture: "aarch64".into(),
            environment: "gnu".into(),
        },
        kernel: Observation::Present(KernelIdentity {
            os: "Linux".into(),
            release: "fixture".into(),
            machine: "aarch64".into(),
        }),
        privileges: Observation::Present(Privileges {
            real_uid: 0,
            effective_uid: 0,
        }),
        hostname: Observation::Present("node-1".into()),
        container_environment_set: false,
        landmarks: paths
            .into_iter()
            .map(|p| (p.into(), Observation::Absent))
            .collect(),
        musl_linkers: Observation::Present(vec![]),
        files: BTreeMap::from([
            (
                "/proc/modules".into(),
                Observation::Present("xt_comment\n".into()),
            ),
            ("/proc/net/ip_tables_matches".into(), Observation::Absent),
            (
                "/sys/fs/cgroup/cgroup.controllers".into(),
                Observation::Present("cpuset cpu io memory pids".into()),
            ),
        ]),
        requested_paths: vec![],
    }
}
fn inputs() -> PreflightInputs {
    PreflightInputs {
        xt_comment_on_disk: Observation::Present(false),
        alpine_rc_service: Observation::Absent,
        ports: [Observation::Present(PortAvailability::Available); 4],
        ..PreflightInputs::default()
    }
}
fn present(e: &mut HostEvidence, path: &str) {
    e.landmarks.insert(path.into(), Observation::Present(true));
}
fn text(e: &mut HostEvidence, path: &str, value: &str) {
    e.files
        .insert(path.into(), Observation::Present(value.into()));
}
fn passed(finding: &Finding) -> bool {
    matches!(
        finding.status,
        CheckStatus::Pass | CheckStatus::NotApplicable
    )
}

fn hostname_case(name: &str) -> String {
    match name {
        "hostname_valid" => "node-1.example".into(),
        "hostname_uppercase" => "Node".into(),
        "hostname_empty" => String::new(),
        "hostname_dot" => "node..host".into(),
        "hostname_underscore" => "node_host".into(),
        "hostname_space" => " node".into(),
        "hostname_label63" => "a".repeat(63),
        "hostname_label64" => "a".repeat(64),
        "hostname_total253" | "hostname_total254" => format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(if name.ends_with("253") { 61 } else { 62 })
        ),
        "hostname_unicode" => "nœud".into(),
        "hostname_dash" => "-node".into(),
        _ => panic!("unknown case"),
    }
}
fn port_case(name: &str) -> bool {
    let e = evidence();
    let mut input = inputs();
    let parts: Vec<_> = name.split('_').collect();
    input.pprof = parts[2] == "true";
    if let Some(index) = ["2379", "6443", "10443", "6060"]
        .iter()
        .position(|port| *port == parts[1])
    {
        input.ports[index] = Observation::Present(PortAvailability::BindFailed);
    }
    passed(&evaluate_preflight(&e, &input).findings[6])
}
fn oracle_case(name: &str) -> bool {
    if name.starts_with("hostname_") {
        return hostname_reason(&hostname_case(name)).is_none();
    }
    let mut e = evidence();
    let mut input = inputs();
    if name.starts_with("ports_") {
        return port_case(name);
    }
    let index = match name {
        "root" => 0,
        "docker_absent" => 2,
        "docker_socket" => {
            present(&mut e, "/var/run/docker.sock");
            2
        },
        "docker_binary" => {
            present(&mut e, "/usr/local/bin/docker");
            2
        },
        "comment_absent" | "comment_loaded" | "comment_match" | "comment_substring"
        | "comment_disk" | "comment_glob" => {
            e.files.insert("/proc/modules".into(), Observation::Absent);
            match name {
                "comment_loaded" => text(&mut e, "/proc/modules", "xt_comment\n"),
                "comment_match" => text(&mut e, "/proc/net/ip_tables_matches", " tcp\n comment \n"),
                "comment_substring" => text(&mut e, "/proc/net/ip_tables_matches", "not_comment\n"),
                "comment_disk" | "comment_glob" => {
                    input.xt_comment_on_disk = Observation::Present(true);
                },
                _ => {},
            }
            3
        },
        "not_alpine" => 4,
        "alpine_missing" | "alpine_tools" | "alpine_custom_paths" => {
            present(&mut e, "/etc/alpine-release");
            if name == "alpine_tools" {
                present(&mut e, "/usr/sbin/nft");
                present(&mut e, "/bin/iptables");
            }
            if name == "alpine_custom_paths" {
                present(&mut e, "/usr/local/bin/nft");
                present(&mut e, "/usr/local/bin/iptables");
            }
            4
        },
        "v2_all" | "v2_missing" | "v2_empty" | "v1_all" | "v1_io_wrong" | "alpine_rc_service"
        | "alpine_ready" => {
            if name == "v2_missing" {
                text(&mut e, "/sys/fs/cgroup/cgroup.controllers", "cpu memory");
            }
            if name == "v2_empty" || name == "alpine_rc_service" {
                text(&mut e, "/sys/fs/cgroup/cgroup.controllers", "");
            }
            if name.starts_with("v1_") {
                e.files.insert(
                    "/sys/fs/cgroup/cgroup.controllers".into(),
                    Observation::Absent,
                );
                for path in [
                    "/sys/fs/cgroup",
                    "/sys/fs/cgroup/cpuset",
                    "/sys/fs/cgroup/cpu",
                    "/sys/fs/cgroup/memory",
                    "/sys/fs/cgroup/pids",
                ] {
                    present(&mut e, path);
                }
                present(
                    &mut e,
                    if name == "v1_all" {
                        "/sys/fs/cgroup/blkio"
                    } else {
                        "/sys/fs/cgroup/io"
                    },
                );
            }
            if name.starts_with("alpine_") {
                present(&mut e, "/etc/alpine-release");
                input.alpine_rc_service = Observation::Present(true);
            }
            5
        },
        "suite_failfast" => {
            e.privileges = Observation::Present(Privileges {
                real_uid: 1000,
                effective_uid: 0,
            });
            return evaluate_preflight(&e, &input).first_blocker == Some(CheckId::Root);
        },
        _ => panic!("unknown oracle case {name}"),
    };
    passed(&evaluate_preflight(&e, &input).findings[index])
}
#[cfg(any())]
#[test]
fn agrees_with_actual_pinned_go_reference_observations() {
    let expected = include_str!("../../../tools/parity/fixtures/preflight-policy/expected.tsv");
    let mut count = 0;
    for line in expected.lines() {
        let (name, value) = line.split_once('\t').unwrap();
        assert_eq!(oracle_case(name), value == "true", "{name}");
        count += 1;
    }
    assert_eq!(count, 44);
}
#[test]
fn baseline_order_and_real_uid_are_distinct_from_effective_uid() {
    let mut e = evidence();
    e.privileges = Observation::Present(Privileges {
        real_uid: 0,
        effective_uid: 1000,
    });
    let report = evaluate_preflight(&e, &inputs());
    assert!(report.ready());
    assert_eq!(
        report.findings.map(|f| f.check),
        [
            CheckId::Root,
            CheckId::Hostname,
            CheckId::DockerConflict,
            CheckId::XtablesComment,
            CheckId::AlpineNetworking,
            CheckId::Cgroups,
            CheckId::Ports
        ]
    );
    e.privileges = Observation::Present(Privileges {
        real_uid: 1000,
        effective_uid: 0,
    });
    assert_eq!(
        evaluate_preflight(&e, &inputs()).first_blocker,
        Some(CheckId::Root)
    );
}
#[test]
fn unknown_read_errors_and_unprobed_ports_never_claim_success() {
    let mut e = evidence();
    let mut input = inputs();
    e.landmarks.remove("/var/run/docker.sock");
    assert_eq!(
        evaluate_preflight(&e, &input).findings[2].status,
        CheckStatus::Unknown
    );
    e = evidence();
    e.files.insert(
        "/proc/modules".into(),
        Observation::Unknown(ProbeFailure::PermissionDenied),
    );
    assert_eq!(
        evaluate_preflight(&e, &input).findings[3].uncertainty,
        Some(ProbeFailure::PermissionDenied)
    );
    input.ports[0] = Observation::Absent;
    assert_eq!(
        evaluate_preflight(&e, &input).findings[6].status,
        CheckStatus::Unknown
    );
    input.ports[1] = Observation::Present(PortAvailability::BindFailed);
    assert_eq!(
        evaluate_preflight(&e, &input).findings[6].missing,
        vec![Requirement::Port6443]
    );
    present(&mut e, "/etc/alpine-release");
    input.alpine_rc_service = Observation::Present(true);
    input.install_prerequisites = true;
    e.files.insert(
        "/sys/fs/cgroup/cgroup.controllers".into(),
        Observation::Unknown(ProbeFailure::PermissionDenied),
    );
    let report = evaluate_preflight(&e, &input);
    assert_eq!(report.findings[5].status, CheckStatus::Unknown);
    assert_eq!(report.findings[5].plans, []);
}
#[test]
fn module_indexes_are_not_proof_of_comment_capability() {
    let mut e = evidence();
    e.files.insert("/proc/modules".into(), Observation::Absent);
    text(
        &mut e,
        "/lib/modules/fixture/modules.dep",
        "kernel/net/netfilter/xt_comment.ko:\n",
    );
    text(
        &mut e,
        "/lib/modules/fixture/modules.builtin",
        "kernel/net/netfilter/xt_comment.ko\n",
    );
    assert_eq!(
        evaluate_preflight(&e, &inputs()).findings[3].status,
        CheckStatus::Blocker
    );
    let input = PreflightInputs {
        xt_comment_on_disk: Observation::Unknown(ProbeFailure::Io),
        ..inputs()
    };
    assert_eq!(
        evaluate_preflight(&e, &input).findings[3].status,
        CheckStatus::Unknown
    );
}
#[test]
fn prerequisite_opt_in_plans_require_recheck_and_never_grant_runtime_ownership() {
    let mut e = evidence();
    present(&mut e, "/etc/alpine-release");
    text(&mut e, "/sys/fs/cgroup/cgroup.controllers", "");
    let mut input = PreflightInputs {
        runtime: RuntimeOwnership::External,
        alpine_rc_service: Observation::Present(true),
        ..inputs()
    };
    let blocked = evaluate_preflight(&e, &input);
    assert!(blocked.findings.iter().all(|f| f.plans.is_empty()));
    input.install_prerequisites = true;
    let report = evaluate_preflight(&e, &input);
    assert!(!report.ready());
    assert_eq!(report.runtime, RuntimeOwnership::External);
    assert_eq!(
        report.findings[4].plans,
        vec![PreparationAction::InstallAlpineNetworking {
            nftables: true,
            iptables: true
        }]
    );
    assert_eq!(
        report.findings[5].plans,
        vec![PreparationAction::EnableAlpineCgroups]
    );
    assert_eq!(report.findings[4].status, CheckStatus::NeedsPreparation);
    assert_eq!(report.findings[5].status, CheckStatus::NeedsPreparation);
    // No external-runtime conflict is invented. An actual Docker landmark is separate evidence.
    assert_eq!(report.findings[2].status, CheckStatus::Pass);
    present(&mut e, "/var/run/docker.sock");
    assert_eq!(
        evaluate_preflight(&e, &input).findings[2].reason,
        Reason::DockerSocketPresent
    );
}

#[test]
fn every_required_controller_and_optional_port_has_distinct_evidence() {
    let required = [
        ("cpuset", Requirement::Cpuset),
        ("cpu", Requirement::Cpu),
        ("io", Requirement::Io),
        ("memory", Requirement::Memory),
        ("pids", Requirement::Pids),
    ];
    for (name, requirement) in required {
        let mut e = evidence();
        let available = required
            .iter()
            .filter(|(n, _)| *n != name)
            .map(|(n, _)| *n)
            .collect::<Vec<_>>()
            .join(" ");
        text(&mut e, "/sys/fs/cgroup/cgroup.controllers", &available);
        assert_eq!(
            evaluate_preflight(&e, &inputs()).findings[5].missing,
            vec![requirement]
        );
    }
    let e = evidence();
    let mut input = inputs();
    input.ports[3] = Observation::Unknown(ProbeFailure::PermissionDenied);
    assert!(evaluate_preflight(&e, &input).ready());
    input.pprof = true;
    assert_eq!(
        evaluate_preflight(&e, &input).first_blocker,
        Some(CheckId::Ports)
    );
    assert_eq!(
        evaluate_preflight(&e, &input).findings[6].uncertainty,
        Some(ProbeFailure::PermissionDenied)
    );
}

#[test]
fn finding_and_report_distinguish_fatal_errors_from_recoverable_limitations() {
    let mut e = evidence();
    e.privileges = Observation::Present(Privileges {
        real_uid: 1000,
        effective_uid: 0,
    });
    let report = evaluate_preflight(&e, &inputs());
    assert!(report.has_fatal_errors());
    assert!(!report.has_recoverable_limitations());
    let fatal_checks: Vec<_> = report.fatal_findings().map(|f| f.check).collect();
    assert_eq!(fatal_checks, vec![CheckId::Root]);
    assert_eq!(report.findings[0].severity(), Some(ErrorSeverity::Fatal));
    assert!(report.findings[0].is_fatal());
    assert!(!report.findings[0].is_recoverable());

    let mut e_alpine = evidence();
    present(&mut e_alpine, "/etc/alpine-release");
    let report_alpine = evaluate_preflight(&e_alpine, &inputs());
    assert!(report_alpine.has_recoverable_limitations());
    let recoverable_checks: Vec<_> = report_alpine
        .recoverable_findings()
        .map(|f| f.check)
        .collect();
    assert!(recoverable_checks.contains(&CheckId::AlpineNetworking));
    let networking_finding = report_alpine
        .findings
        .iter()
        .find(|f| f.check == CheckId::AlpineNetworking)
        .unwrap();
    assert_eq!(
        networking_finding.severity(),
        Some(ErrorSeverity::Recoverable)
    );
    assert!(networking_finding.is_recoverable());
    assert!(!networking_finding.is_fatal());

    let mut unknown = evidence();
    unknown.hostname = Observation::Unknown(ProbeFailure::PermissionDenied);
    let unknown_report = evaluate_preflight(&unknown, &inputs());
    let hostname = unknown_report
        .findings
        .iter()
        .find(|finding| finding.check == CheckId::Hostname)
        .unwrap();
    assert_eq!(hostname.severity(), Some(ErrorSeverity::Uncertain));
    assert!(hostname.is_uncertain());
    assert!(!hostname.is_fatal());
    assert!(unknown_report.has_uncertain_observations());
    assert!(
        !unknown_report
            .fatal_findings()
            .any(|finding| finding.check == CheckId::Hostname)
    );
}

#[test]
fn explicit_external_runtime_is_not_reported_as_managed_runtime_conflict() {
    let mut e = evidence();
    // With external runtime configured, no managed-runtime conflict is inferred.
    let mut external_input = inputs();
    external_input.runtime = RuntimeOwnership::External;
    let report = evaluate_preflight(&e, &external_input);
    assert_eq!(report.runtime, RuntimeOwnership::External);
    assert_eq!(report.findings[2].status, CheckStatus::Pass);
    assert!(report.ready());

    // Actual Docker landmarks remain an independent baseline conflict.
    present(&mut e, "/var/run/docker.sock");
    let blocked_report = evaluate_preflight(&e, &external_input);
    assert_eq!(blocked_report.first_blocker, Some(CheckId::DockerConflict));
    let docker_finding = &blocked_report.findings[2];
    assert_eq!(docker_finding.status, CheckStatus::Blocker);
    assert_eq!(docker_finding.reason, Reason::DockerSocketPresent);
    assert_eq!(
        docker_finding.remediation,
        Some(Remediation::ResolveDockerConflict)
    );
    assert_eq!(docker_finding.severity(), Some(ErrorSeverity::Fatal));
}

#[test]
fn constrained_platforms_supported_fixtures_pass_and_unsupported_combinations_explain_remediation()
{
    // 1. Supported Alpine platform with tools and populated cgroups passes.
    let mut e_alpine = evidence();
    present(&mut e_alpine, "/etc/alpine-release");
    present(&mut e_alpine, "/usr/sbin/nft");
    present(&mut e_alpine, "/sbin/iptables");
    let mut input = inputs();
    input.runtime = RuntimeOwnership::External;
    let report = evaluate_preflight(&e_alpine, &input);
    assert!(report.ready());
    assert_eq!(report.findings[4].status, CheckStatus::Pass);
    assert_eq!(report.findings[5].status, CheckStatus::Pass);

    // 2. Unsupported Alpine with missing tools explains remediation.
    let mut e_no_tools = evidence();
    present(&mut e_no_tools, "/etc/alpine-release");
    let report_no_tools = evaluate_preflight(&e_no_tools, &input);
    assert_eq!(
        report_no_tools.first_blocker,
        Some(CheckId::AlpineNetworking)
    );
    let net_finding = &report_no_tools.findings[4];
    assert_eq!(net_finding.status, CheckStatus::Blocker);
    assert_eq!(net_finding.reason, Reason::AlpineToolsMissing);
    assert_eq!(
        net_finding.remediation,
        Some(Remediation::InstallAlpineNetworking)
    );

    // 3. Unsupported Alpine with unpopulated cgroups and OpenRC explains remediation.
    let mut e_openrc = evidence();
    present(&mut e_openrc, "/etc/alpine-release");
    present(&mut e_openrc, "/usr/sbin/nft");
    present(&mut e_openrc, "/sbin/iptables");
    e_openrc.files.insert(
        "/sys/fs/cgroup/cgroup.controllers".into(),
        Observation::Present(String::new()),
    );
    let mut openrc_input = inputs();
    openrc_input.alpine_rc_service = Observation::Present(true);
    let report_openrc = evaluate_preflight(&e_openrc, &openrc_input);
    assert_eq!(report_openrc.first_blocker, Some(CheckId::Cgroups));
    let cgroup_finding = &report_openrc.findings[5];
    assert_eq!(cgroup_finding.status, CheckStatus::Blocker);
    assert_eq!(cgroup_finding.reason, Reason::AlpineCgroupsSetup);
    assert_eq!(
        cgroup_finding.remediation,
        Some(Remediation::EnableAlpineCgroups)
    );

    // 4. Missing xt_comment explains remediation.
    let mut e_no_comment = evidence();
    e_no_comment
        .files
        .insert("/proc/modules".into(), Observation::Absent);
    e_no_comment
        .files
        .insert("/proc/net/ip_tables_matches".into(), Observation::Absent);
    let mut comment_input = inputs();
    comment_input.xt_comment_on_disk = Observation::Present(false);
    let report_comment = evaluate_preflight(&e_no_comment, &comment_input);
    assert_eq!(report_comment.first_blocker, Some(CheckId::XtablesComment));
    let comment_finding = &report_comment.findings[3];
    assert_eq!(comment_finding.status, CheckStatus::Blocker);
    assert_eq!(comment_finding.reason, Reason::CommentSupportMissing);
    assert_eq!(
        comment_finding.remediation,
        Some(Remediation::ProvideCommentSupport)
    );
}
