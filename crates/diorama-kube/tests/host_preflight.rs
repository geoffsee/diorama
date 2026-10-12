use diorama::host_preflight::*;
use diorama_platform::constrained::*;
use diorama_platform::preflight::*;
use diorama_platform::preflight_probe::SupplementalFacts;
use diorama_platform::*;
use diorama_supervisor::StopReceiver;
use diorama_supervisor::process::{ProcessCleanupSnapshot, ProcessExit};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
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
#[derive(Default, PartialEq, Eq)]
enum VersionMode {
    #[default]
    Success,
    Fail,
    Incomplete,
    Wait,
    Real,
    OwnerLaunch,
}
struct Fake {
    facts: HostEvidence,
    calls: Rc<RefCell<Vec<&'static str>>>,
    mode: VersionMode,
    unknown_ipv6: bool,
    wake: Option<tokio::sync::oneshot::Sender<()>>,
}
impl Default for Fake {
    fn default() -> Self {
        let mut facts = evidence();
        facts
            .landmarks
            .insert("/sys/fs/cgroup".into(), Observation::Present(true));
        Self {
            facts,
            calls: Rc::default(),
            mode: VersionMode::Success,
            unknown_ipv6: false,
            wake: None,
        }
    }
}
impl AssessmentInputs for Fake {
    fn discover(&mut self, request: &DiscoveryRequest) -> Result<HostEvidence, PlatformError> {
        self.calls.borrow_mut().push("discover");
        assert_eq!(request.paths.len(), 1);
        Ok(self.facts.clone())
    }
    fn supplemental(&mut self, _: ProbeLimits) -> Result<SupplementalFacts, PlatformError> {
        self.calls.borrow_mut().push("supplemental");
        Ok(SupplementalFacts {
            xt_comment_on_disk: Observation::Present(false),
            alpine_rc_service: Observation::Absent,
        })
    }
    fn constrained(&mut self, _: ProbeLimits) -> Result<ConstrainedFacts, PlatformError> {
        self.calls.borrow_mut().push("constrained");
        if let Some(wake) = self.wake.take() {
            let _ = wake.send(());
        }
        Ok(ConstrainedFacts {
            sysctls: std::array::from_fn(|index| {
                if index > 0 && self.unknown_ipv6 {
                    Observation::Unknown(ProbeFailure::PermissionDenied)
                } else {
                    Observation::Present("1\n".into())
                }
            }),
            proc_sys_read_only: Observation::Present(false),
            ip_tables_names: Observation::Absent,
            default_cni_plugins: [Observation::Absent; 4],
            cni_config_names: Observation::Present(vec!["01-host.conflist".into()]),
        })
    }
    fn ports(&mut self, pprof: bool) -> Result<[Observation<PortAvailability>; 4], PlatformError> {
        self.calls.borrow_mut().push("ports");
        assert!(!pprof);
        Ok([Observation::Present(PortAvailability::Available); 4])
    }
    async fn version(&mut self, stop: StopReceiver) -> VersionProbe {
        self.calls.borrow_mut().push("version");
        if self.mode == VersionMode::OwnerLaunch {
            return VersionProbe {
                family: Observation::Unknown(ProbeFailure::Io),
                failure: Some(VersionFailure::Command),
                cleanup: ProcessCleanupSnapshot {
                    started: true,
                    error: Some("process_owner_spawn_failed"),
                    ..Default::default()
                },
                observer: None,
            };
        }
        if self.mode == VersionMode::Real {
            return iptables_version(stop).await;
        }
        if self.mode == VersionMode::Wait {
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
        }
        VersionProbe {
            family: if self.mode == VersionMode::Fail {
                Observation::Unknown(ProbeFailure::Io)
            } else {
                Observation::Present(ModuleFamily::Legacy)
            },
            failure: (self.mode == VersionMode::Fail).then_some(VersionFailure::Command),
            cleanup: ProcessCleanupSnapshot {
                started: true,
                spawned: true,
                leader_reaped: true,
                thread_finished: true,
                thread_joined: self.mode != VersionMode::Incomplete,
                exit: Some(ProcessExit {
                    code: Some(0),
                    signal: None,
                }),
                ..Default::default()
            },
            observer: None,
        }
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
#[tokio::test]
async fn external_config_keeps_independent_backend_and_host_ownership() {
    let mut fake = Fake::default();
    let report = assess_node_with(&config(true, false), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, AssessmentStatus::Observed);
    assert_eq!(report.runtime, RuntimeOwnership::External);
    assert_eq!(report.container_mode, Observation::Present(false));
    assert_eq!(report.container_preparation, RequirementState::NotRequested);
    assert_eq!(report.ipv6_disable, [None; 3]);
    let constrained = report.constrained.unwrap();
    assert_eq!(
        constrained.responsibilities,
        RuntimeResponsibilities::External
    );
    assert_eq!(
        constrained.proxy_selection,
        Observation::Present(ProxyBackend::Nftables)
    );
    assert_eq!(
        constrained.module_family,
        Observation::Present(ModuleFamily::Legacy)
    );
    assert_eq!(
        constrained.plugins,
        [PluginState::DefaultLocationMissing; 4]
    );
    assert_eq!(
        constrained.cni_ordering,
        Observation::Present(CniOrdering {
            earlier: 1,
            later: 0
        })
    );
    assert_eq!(
        *fake.calls.borrow(),
        [
            "discover",
            "supplemental",
            "constrained",
            "version",
            "ports"
        ]
    );
}
#[tokio::test]
async fn earlier_root_blocker_prevents_command_and_ports() {
    let mut fake = Fake::default();
    fake.facts.privileges = Observation::Present(Privileges {
        real_uid: 1,
        effective_uid: 1,
    });
    let report = assess_node_with(&config(false, false), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, AssessmentStatus::Blocked);
    assert_eq!(*fake.calls.borrow(), ["discover", "supplemental"]);
}
#[tokio::test]
async fn failed_command_never_becomes_nft_or_probes_ports() {
    let mut fake = Fake {
        mode: VersionMode::Fail,
        ..Default::default()
    };
    let report = assess_node_with(&config(false, false), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, AssessmentStatus::Unknown);
    assert_eq!(
        report.constrained.unwrap().module_family,
        Observation::Unknown(ProbeFailure::Io)
    );
    assert!(!fake.calls.borrow().contains(&"ports"));
}
#[tokio::test]
async fn cancellation_before_start_and_between_phases_latches_without_send_bound() {
    let mut fake = Fake::default();
    assert_eq!(
        assess_node_with(&config(false, false), async {}, &mut fake)
            .await
            .status,
        AssessmentStatus::Cancelled
    );
    assert!(fake.calls.borrow().is_empty());
    let (wake, receiver) = tokio::sync::oneshot::channel();
    fake.wake = Some(wake);
    let report = assess_node_with(
        &config(false, false),
        async {
            let _ = receiver.await;
        },
        &mut fake,
    )
    .await;
    assert_eq!(report.status, AssessmentStatus::Cancelled);
    assert_eq!(
        *fake.calls.borrow(),
        ["discover", "supplemental", "constrained"]
    );
}
#[tokio::test]
async fn unrequested_ipv6_is_not_a_write_requirement_but_requested_unknown_blocks() {
    for requested in [false, true] {
        let mut fake = Fake {
            unknown_ipv6: true,
            ..Default::default()
        };
        let report =
            assess_node_with(&config(false, requested), std::future::pending(), &mut fake).await;
        assert_eq!(
            report.status,
            if requested {
                AssessmentStatus::Unknown
            } else {
                AssessmentStatus::Observed
            }
        );
        assert_eq!(fake.calls.borrow().contains(&"version"), !requested);
    }
}

#[tokio::test]
async fn incomplete_owner_prevents_all_post_probe_effects() {
    let mut fake = Fake {
        mode: VersionMode::Incomplete,
        ..Default::default()
    };
    let result = assess_node_with(&config(false, false), std::future::pending(), &mut fake).await;
    assert_eq!(result.status, AssessmentStatus::CleanupIncomplete);
    assert!(!fake.calls.borrow().contains(&"ports"));
}
#[tokio::test]
async fn cancellation_during_probe_waits_for_provider_stop_acknowledgement() {
    let mut fake = Fake {
        mode: VersionMode::Wait,
        ..Default::default()
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        assess_node_with(
            &config(false, false),
            tokio::time::sleep(std::time::Duration::from_millis(30)),
            &mut fake,
        ),
    )
    .await
    .unwrap();
    assert_eq!(result.status, AssessmentStatus::Cancelled);
    assert!(fake.calls.borrow().contains(&"version"));
    assert!(!fake.calls.borrow().contains(&"ports"));
}

#[tokio::test]
#[ignore = "actual fixed-path probe only in disposable namespace"]
async fn disposable_configured_assessment() {
    assert_eq!(std::env::var("diorama_NODE_DISPOSABLE").as_deref(), Ok("1"));
    std::fs::write("/tmp/probe-mode", "nft").unwrap();
    let mut fake = Fake {
        mode: VersionMode::Real,
        ..Default::default()
    };
    let report = assess_node_with(&config(true, false), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, AssessmentStatus::Observed);
    assert_eq!(report.runtime, RuntimeOwnership::External);
    assert_eq!(
        report.constrained.unwrap().module_family,
        Observation::Present(ModuleFamily::NfTables)
    );
    assert_eq!(
        *fake.calls.borrow(),
        [
            "discover",
            "supplemental",
            "constrained",
            "version",
            "ports"
        ]
    );
    println!("diorama_NODE_ASSESSMENT external=true real_probe=true injected_host_facts=true");
}

#[tokio::test]
async fn container_override_and_unknown_detection_remain_distinct() {
    for explicit in [None, Some(false), Some(true)] {
        let mut desired = config(false, true).into_config();
        desired.runtime.container_mode = explicit;
        let desired = desired
            .validate(&diorama_config::HostContext {
                cpu_count: 4,
                architecture: "arm64".into(),
                detected_container_mode: false,
            })
            .unwrap();
        let mut fake = Fake::default();
        fake.facts.landmarks.insert(
            "/.dockerenv".into(),
            Observation::Unknown(ProbeFailure::PermissionDenied),
        );
        let report = assess_node_with(&desired, std::future::pending(), &mut fake).await;
        match explicit {
            None => {
                assert_eq!(report.status, AssessmentStatus::Unknown);
                assert_eq!(
                    report.container_preparation,
                    RequirementState::Unknown(ProbeFailure::PermissionDenied)
                );
                assert!(!fake.calls.borrow().contains(&"version"));
            },
            Some(value) => {
                assert_eq!(report.status, AssessmentStatus::Observed);
                assert_eq!(report.container_mode, Observation::Present(value));
                assert_eq!(
                    report.container_preparation,
                    if value {
                        RequirementState::Required
                    } else {
                        RequirementState::NotRequested
                    }
                );
                assert_eq!(report.ipv6_disable, [Some(SysctlState::AlreadyCorrect); 3]);
            },
        }
    }
}

#[tokio::test]
async fn owner_launch_failure_reports_unknown_command_without_ports_or_quiet_exit() {
    let mut fake = Fake {
        mode: VersionMode::OwnerLaunch,
        ..Default::default()
    };
    let result = assess_node_with(&config(false, false), std::future::pending(), &mut fake).await;
    assert_eq!(result.status, AssessmentStatus::Unknown);
    assert_eq!(
        result.version.unwrap().failure,
        Some(VersionFailure::Command)
    );
    assert!(!fake.calls.borrow().contains(&"ports"));
}

#[tokio::test]
async fn external_runtime_assessment_preserves_external_responsibilities_and_docker_conflict() {
    let mut fake = Fake::default();
    let report = assess_node_with(&config(true, false), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, AssessmentStatus::Observed);
    assert_eq!(report.runtime, RuntimeOwnership::External);
    assert_eq!(
        report.constrained.as_ref().unwrap().responsibilities,
        RuntimeResponsibilities::External
    );

    // Docker conflict remains an independent check.
    let mut fake_docker = Fake::default();
    fake_docker
        .facts
        .landmarks
        .insert("/var/run/docker.sock".into(), Observation::Present(true));
    let blocked = assess_node_with(
        &config(true, false),
        std::future::pending(),
        &mut fake_docker,
    )
    .await;
    assert_eq!(blocked.status, AssessmentStatus::Blocked);
    assert_eq!(
        blocked.preflight.as_ref().unwrap().first_blocker,
        Some(CheckId::DockerConflict)
    );
    assert_eq!(
        fake.calls.borrow().as_slice(),
        [
            "discover",
            "supplemental",
            "constrained",
            "version",
            "ports"
        ]
    );
    assert_eq!(
        fake_docker.calls.borrow().as_slice(),
        ["discover", "supplemental"]
    );

    let mut missing_comment = Fake::default();
    missing_comment
        .facts
        .files
        .insert("/proc/modules".into(), Observation::Present(String::new()));
    missing_comment
        .facts
        .files
        .insert("/proc/net/ip_tables_matches".into(), Observation::Absent);
    let comment_blocked = assess_node_with(
        &config(true, false),
        std::future::pending(),
        &mut missing_comment,
    )
    .await;
    assert_eq!(comment_blocked.status, AssessmentStatus::Blocked);
    assert_eq!(
        comment_blocked.preflight.as_ref().unwrap().first_blocker,
        Some(CheckId::XtablesComment)
    );
    assert_eq!(
        comment_blocked
            .preflight
            .as_ref()
            .unwrap()
            .findings
            .iter()
            .find(|finding| finding.check == CheckId::XtablesComment)
            .unwrap()
            .status,
        CheckStatus::Blocker
    );
    assert_eq!(
        missing_comment.calls.borrow().as_slice(),
        ["discover", "supplemental"]
    );
    assert!(comment_blocked.constrained.is_none());
}
