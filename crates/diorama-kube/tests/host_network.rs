//! Injected boundary tests: these never execute modprobe or touch host sysctls.
use diorama::host_network::*;
use diorama::host_preflight::*;
use diorama_platform::constrained::*;
use diorama_platform::preflight::*;
use diorama_platform::preflight_probe::SupplementalFacts;
use diorama_platform::*;
use diorama_supervisor::StopReceiver;
use diorama_supervisor::process::{ProcessCleanupSnapshot, ProcessExit};
use std::collections::{BTreeMap, VecDeque};
fn evidence() -> HostEvidence {
    let paths = [
        "/.dockerenv",
        "/run/.containerenv",
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
fn config(external: bool, disable_ipv6: bool) -> diorama_config::ValidatedConfig {
    let mut config = diorama_config::Config::default();
    if external {
        config.runtime.endpoint = "unix:///host/containerd.sock".into();
    }
    config.runtime.container_mode = Some(false);
    config.network.disable_ipv6 = disable_ipv6;
    config
        .validate(&diorama_config::HostContext {
            cpu_count: 4,
            architecture: "arm64".into(),
            detected_container_mode: true,
        })
        .unwrap()
}

#[allow(clippy::struct_excessive_bools)] // Independent injected failure switches, not production state.
struct Fake {
    facts: HostEvidence,
    family: Observation<ModuleFamily>,
    module_outcome: CommandOutcome,
    unjoined: bool,
    spawn: bool,
    modules: Vec<ModuleId>,
    reads: VecDeque<Result<Scalar, SysctlError>>,
    controls: Vec<Ipv6Control>,
    writes: Vec<Ipv6Control>,
    write_error: Option<SysctlError>,
    cancel_on_read: Option<tokio::sync::oneshot::Sender<()>>,
    cancel_on_write: Option<tokio::sync::oneshot::Sender<()>>,
    wait_for_stop: bool,
    stop_acknowledged: bool,
    ipv4_unknown: bool,
}
impl Default for Fake {
    fn default() -> Self {
        let mut facts = evidence();
        facts
            .landmarks
            .insert("/sys/fs/cgroup".into(), Observation::Present(true));
        Self {
            facts,
            family: Observation::Present(ModuleFamily::Legacy),
            module_outcome: CommandOutcome::Success,
            unjoined: false,
            spawn: true,
            modules: vec![],
            reads: VecDeque::new(),
            controls: vec![],
            writes: vec![],
            write_error: None,
            cancel_on_read: None,
            cancel_on_write: None,
            wait_for_stop: false,
            stop_acknowledged: false,
            ipv4_unknown: false,
        }
    }
}
fn cleanup(spawn: bool) -> ProcessCleanupSnapshot {
    ProcessCleanupSnapshot {
        started: true,
        spawned: spawn,
        leader_reaped: spawn,
        thread_finished: true,
        thread_joined: true,
        exit: spawn.then_some(ProcessExit {
            code: Some(0),
            signal: None,
        }),
        ..Default::default()
    }
}
impl AssessmentInputs for Fake {
    fn discover(&mut self, _: &DiscoveryRequest) -> Result<HostEvidence, PlatformError> {
        Ok(self.facts.clone())
    }
    fn supplemental(&mut self, _: ProbeLimits) -> Result<SupplementalFacts, PlatformError> {
        Ok(SupplementalFacts {
            xt_comment_on_disk: Observation::Present(false),
            alpine_rc_service: Observation::Absent,
        })
    }
    fn constrained(&mut self, _: ProbeLimits) -> Result<ConstrainedFacts, PlatformError> {
        Ok(ConstrainedFacts {
            sysctls: std::array::from_fn(|i| {
                if i == 0 && !self.ipv4_unknown {
                    Observation::Present("1\n".into())
                } else {
                    Observation::Unknown(ProbeFailure::PermissionDenied)
                }
            }),
            proc_sys_read_only: Observation::Present(false),
            ip_tables_names: Observation::Absent,
            default_cni_plugins: [Observation::Absent; 4],
            cni_config_names: Observation::Present(vec![]),
        })
    }
    fn ports(&mut self, _: bool) -> Result<[Observation<PortAvailability>; 4], PlatformError> {
        Ok([Observation::Present(PortAvailability::Available); 4])
    }
    async fn version(&mut self, _: StopReceiver) -> VersionProbe {
        VersionProbe {
            family: self.family,
            failure: None,
            cleanup: cleanup(true),
            observer: None,
        }
    }
}
impl NetworkPreparationInputs for Fake {
    async fn load_module(&mut self, module: ModuleId, stop: StopReceiver) -> ModuleCommand {
        self.modules.push(module);
        if self.wait_for_stop {
            use diorama_supervisor::process::ExternalServiceAdapter;
            use diorama_supervisor::{
                ComponentKind, ComponentSpec, FailurePolicy, Registration, Supervisor,
            };
            let spec = ComponentSpec {
                id: "fake".into(),
                prerequisites: vec![],
                kind: ComponentKind::LongRunning,
                failure_policy: FailurePolicy::Fatal,
                startup_timeout: std::time::Duration::from_secs(1),
            };
            Supervisor::new(vec![Registration::new(
                spec,
                ExternalServiceAdapter::new(async { Ok(()) }),
            )])
            .unwrap()
            .run(stop)
            .await;
            self.stop_acknowledged = true;
        }
        let mut settled = cleanup(self.spawn);
        settled.thread_joined = !self.unjoined;
        ModuleCommand {
            outcome: self.module_outcome,
            cleanup: settled,
            observer: None,
        }
    }
    fn observe_module(&mut self, _: ModuleId) -> ModuleObservation {
        ModuleObservation {
            loaded: Observation::Present(false),
            builtin_index: Observation::Absent,
            available_index: Observation::Unknown(ProbeFailure::PermissionDenied),
        }
    }
    fn read_ipv6(&mut self, control: Ipv6Control) -> Result<Scalar, SysctlError> {
        self.controls.push(control);
        if let Some(wake) = self.cancel_on_read.take() {
            let _ = wake.send(());
        }
        self.reads.pop_front().unwrap_or(Ok(Scalar::Disabled))
    }
    fn write_ipv6_disabled(&mut self, control: Ipv6Control) -> Result<(), SysctlError> {
        self.writes.push(control);
        if let Some(wake) = self.cancel_on_write.take() {
            let _ = wake.send(());
        }
        self.write_error.map_or(Ok(()), Err)
    }
}
#[tokio::test]
async fn fixed_backend_lists_and_external_runtime_keep_network_effects() {
    for (family, expected_backend) in [
        (
            ModuleFamily::Legacy,
            ["ip_tables", "iptable_filter", "iptable_nat", "nf_conntrack"].as_slice(),
        ),
        (
            ModuleFamily::NfTables,
            [
                "nft_compat",
                "nft_numgen",
                "nft_redir",
                "nft_limit",
                "nft_tproxy",
            ]
            .as_slice(),
        ),
    ] {
        let mut fake = Fake {
            family: Observation::Present(family),
            ..Default::default()
        };
        let report =
            prepare_node_network_with(&config(true, false), std::future::pending(), &mut fake)
                .await;
        assert_eq!(report.status, NetworkStatus::Completed);
        assert_eq!(fake.modules.len(), 8 + expected_backend.len());
        assert_eq!(
            fake.modules[..8]
                .iter()
                .map(|m| m.name())
                .collect::<Vec<_>>(),
            [
                "br_netfilter",
                "overlay",
                "xt_comment",
                "xt_conntrack",
                "xt_MASQUERADE",
                "xt_addrtype",
                "xt_multiport",
                "xt_nat"
            ]
        );
        assert_eq!(
            fake.modules[8..]
                .iter()
                .map(|m| m.name())
                .collect::<Vec<_>>(),
            expected_backend
        );
        assert!(report.shared_effects_possible);
        assert!(report.ipv6.is_empty());
        assert!(
            report
                .modules
                .iter()
                .all(|s| s.after.as_ref().unwrap().loaded == Observation::Present(false))
        );
    }
}
#[tokio::test]
async fn fresh_root_backend_and_ipv4_unknown_guards_prevent_effects() {
    for scenario in 0..3 {
        let mut fake = Fake::default();
        match scenario {
            0 => {
                fake.facts.privileges = Observation::Present(Privileges {
                    real_uid: 1,
                    effective_uid: 1,
                });
            },
            1 => fake.family = Observation::Unknown(ProbeFailure::Io),
            _ => fake.ipv4_unknown = true,
        }
        let report =
            prepare_node_network_with(&config(false, true), std::future::pending(), &mut fake)
                .await;
        assert_eq!(report.status, NetworkStatus::GuardStopped);
        assert!(fake.modules.is_empty() && fake.controls.is_empty() && fake.writes.is_empty());
        assert!(!report.shared_effects_possible);
    }
}
#[tokio::test]
async fn settled_module_failures_warn_and_continue_without_loaded_claim() {
    for outcome in [
        CommandOutcome::Failed,
        CommandOutcome::Deadline,
        CommandOutcome::CaptureFailed,
    ] {
        let mut fake = Fake {
            module_outcome: outcome,
            ..Default::default()
        };
        let report =
            prepare_node_network_with(&config(false, true), std::future::pending(), &mut fake)
                .await;
        assert_eq!(report.status, NetworkStatus::Completed);
        assert_eq!(report.modules.len(), 12);
        assert_eq!(report.ipv6.len(), 3);
        assert!(report.modules.iter().all(|s| s.command.outcome == outcome));
        assert!(report.shared_effects_possible);
    }
}
#[tokio::test]
async fn unjoined_module_owner_stops_all_further_effects() {
    let mut fake = Fake {
        unjoined: true,
        ..Default::default()
    };
    let report =
        prepare_node_network_with(&config(false, true), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, NetworkStatus::CleanupIncomplete);
    assert_eq!(report.modules.len(), 1);
    assert!(report.modules[0].after.is_none());
    assert!(fake.controls.is_empty());
    assert!(report.shared_effects_possible);
}
#[tokio::test]
async fn cancellation_before_start_never_observes_or_mutates_network() {
    let mut fake = Fake::default();
    let report = prepare_node_network_with(&config(false, true), async {}, &mut fake).await;
    assert_eq!(report.status, NetworkStatus::Cancelled);
    assert!(fake.modules.is_empty() && fake.controls.is_empty());
    assert!(!report.shared_effects_possible);
}
#[tokio::test]
async fn cancellation_during_module_waits_for_stop_acknowledgement() {
    let mut fake = Fake {
        wait_for_stop: true,
        ..Default::default()
    };
    let report = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        prepare_node_network_with(
            &config(false, true),
            tokio::time::sleep(std::time::Duration::from_millis(20)),
            &mut fake,
        ),
    )
    .await
    .unwrap();
    assert_eq!(report.status, NetworkStatus::Cancelled);
    assert!(fake.stop_acknowledged);
    assert_eq!(fake.modules.len(), 1);
    assert!(fake.controls.is_empty());
    assert!(report.shared_effects_possible);
}
#[tokio::test]
async fn requested_unknown_ipv6_is_deferred_only_by_preparation() {
    let mut fake = Fake::default();
    let assessment =
        assess_node_with(&config(false, true), std::future::pending(), &mut fake).await;
    assert_eq!(assessment.status, AssessmentStatus::Unknown);
    fake.reads = VecDeque::from([
        Err(SysctlError::Missing),
        Err(SysctlError::PermissionDenied),
        Err(SysctlError::Malformed),
    ]);
    let report =
        prepare_node_network_with(&config(false, true), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, NetworkStatus::Completed);
    assert_eq!(
        report
            .ipv6
            .iter()
            .map(|s| s.outcome.clone())
            .collect::<Vec<_>>(),
        [
            Ipv6Outcome::Skipped(SysctlError::Missing),
            Ipv6Outcome::Skipped(SysctlError::PermissionDenied),
            Ipv6Outcome::Unreadable(SysctlError::Malformed)
        ]
    );
    assert!(fake.writes.is_empty());
}
#[tokio::test]
async fn ipv6_only_zero_writes_and_success_requires_readback() {
    let mut fake = Fake {
        reads: VecDeque::from([
            Ok(Scalar::Disabled),
            Ok(Scalar::Enabled),
            Ok(Scalar::Disabled),
            Ok(Scalar::Enabled),
            Ok(Scalar::Enabled),
        ]),
        ..Default::default()
    };
    let report =
        prepare_node_network_with(&config(false, true), std::future::pending(), &mut fake).await;
    assert_eq!(
        report
            .ipv6
            .iter()
            .map(|s| s.outcome.clone())
            .collect::<Vec<_>>(),
        [
            Ipv6Outcome::AlreadyDisabled,
            Ipv6Outcome::ObservedDisabled,
            Ipv6Outcome::Readback(Ok(Scalar::Enabled))
        ]
    );
    assert_eq!(fake.writes, [Ipv6Control::Default, Ipv6Control::Loopback]);
}
#[tokio::test]
async fn write_failures_continue_to_all_controls_and_retain_possible_effects() {
    let mut fake = Fake {
        spawn: false,
        write_error: Some(SysctlError::PermissionDenied),
        reads: VecDeque::from([Ok(Scalar::Enabled); 3]),
        ..Default::default()
    };
    let report =
        prepare_node_network_with(&config(false, true), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, NetworkStatus::Completed);
    assert_eq!(fake.writes.len(), 3);
    assert!(report.shared_effects_possible);
    assert!(
        report
            .ipv6
            .iter()
            .all(|s| s.outcome == Ipv6Outcome::WriteFailed(SysctlError::PermissionDenied))
    );
}
#[tokio::test]
async fn cancellation_between_ipv6_read_and_write_prevents_write() {
    let (wake, receive) = tokio::sync::oneshot::channel();
    let mut fake = Fake {
        spawn: false,
        cancel_on_read: Some(wake),
        reads: VecDeque::from([Ok(Scalar::Enabled)]),
        ..Default::default()
    };
    let report = prepare_node_network_with(
        &config(false, true),
        async {
            let _ = receive.await;
        },
        &mut fake,
    )
    .await;
    assert_eq!(report.status, NetworkStatus::Cancelled);
    assert_eq!(report.ipv6[0].outcome, Ipv6Outcome::CancelledBeforeWrite);
    assert!(fake.writes.is_empty());
    assert!(!report.shared_effects_possible);
}
#[tokio::test]
async fn cancellation_after_ipv6_write_preserves_possible_effects_without_readback() {
    let (wake, receive) = tokio::sync::oneshot::channel();
    let mut fake = Fake {
        spawn: false,
        cancel_on_write: Some(wake),
        reads: VecDeque::from([Ok(Scalar::Enabled)]),
        ..Default::default()
    };
    let report = prepare_node_network_with(
        &config(false, true),
        async {
            let _ = receive.await;
        },
        &mut fake,
    )
    .await;
    assert_eq!(report.status, NetworkStatus::Cancelled);
    assert_eq!(report.ipv6[0].outcome, Ipv6Outcome::CancelledAfterWrite);
    assert_eq!(fake.controls.len(), 1);
    assert_eq!(fake.writes.len(), 1);
    assert!(report.shared_effects_possible);
}
#[test]
fn complete_bounded_scalars_reject_prefixes_and_binary_data() {
    for value in [b"0".as_slice(), b" 0\n"] {
        assert_eq!(parse_ipv6_scalar(value), Ok(Scalar::Enabled));
    }
    for value in [b"1".as_slice(), b"\t1\n"] {
        assert_eq!(parse_ipv6_scalar(value), Ok(Scalar::Disabled));
    }
    for value in [b"10".as_slice(), b"", b"1\0", b"0 1", b"-1", b"2"] {
        assert_eq!(parse_ipv6_scalar(value), Err(SysctlError::Malformed));
    }
    assert_eq!(parse_ipv6_scalar(&[b' '; 65]), Err(SysctlError::TooLarge));
}

#[test]
fn owner_launch_failure_has_no_child_and_is_settled() {
    let command = ModuleCommand {
        outcome: CommandOutcome::Failed,
        cleanup: ProcessCleanupSnapshot {
            started: true,
            error: Some("process_owner_spawn_failed"),
            ..Default::default()
        },
        observer: None,
    };
    assert!(!command.cleanup_uncertain());
    assert!(!command.cleanup.spawned);
}
#[tokio::test]
async fn cancellation_after_failed_write_retains_possible_effects() {
    let (wake, receive) = tokio::sync::oneshot::channel();
    let mut fake = Fake {
        spawn: false,
        cancel_on_write: Some(wake),
        write_error: Some(SysctlError::Io),
        reads: VecDeque::from([Ok(Scalar::Enabled)]),
        ..Default::default()
    };
    let report = prepare_node_network_with(
        &config(false, true),
        async {
            let _ = receive.await;
        },
        &mut fake,
    )
    .await;
    assert_eq!(report.status, NetworkStatus::Cancelled);
    assert_eq!(report.ipv6[0].outcome, Ipv6Outcome::CancelledAfterWrite);
    assert!(report.shared_effects_possible);
    assert_eq!(fake.writes.len(), 1);
    assert_eq!(fake.controls.len(), 1);
}
