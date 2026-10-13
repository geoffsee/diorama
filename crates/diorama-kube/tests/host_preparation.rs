//! Combined sequencing with injected facts and effects only; no host mutations.
use diorama::host_container::ContainerError;
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
fn config(external: bool, container_mode: bool) -> diorama_config::ValidatedConfig {
    let mut config = diorama_config::Config::default();
    if external {
        config.runtime.endpoint = "unix:///host/containerd.sock".into();
    }
    config.runtime.container_mode = Some(container_mode);
    config.network.disable_ipv6 = false;
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
    container_calls: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    settled_modules: usize,
    init_error: Option<ContainerError>,
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
            container_calls: std::sync::Arc::default(),
            settled_modules: 0,
            init_error: None,
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
    fn version(&mut self, _: StopReceiver) -> impl std::future::Future<Output = VersionProbe> {
        let probe = VersionProbe {
            family: self.family,
            failure: None,
            cleanup: cleanup(true),
            observer: None,
        };
        std::future::ready(probe)
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
use diorama::host_container::*;
use diorama::host_preparation::*;
struct Session {
    calls: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    init_error: Option<ContainerError>,
}
impl Session {
    fn record(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }
    fn mutation(&self, call: &'static str) -> Mutation {
        self.record(call);
        Mutation {
            attempted: true,
            result: Ok(()),
        }
    }
}
impl ContainerPreparationInputs for Fake {
    type Session = Session;
    fn container_session(&mut self) -> Result<Session, ContainerError> {
        let added = self.modules.len() - self.settled_modules;
        assert_eq!(
            added, 12,
            "all settled network module attempts precede container effects"
        );
        self.settled_modules = self.modules.len();
        let session = Session {
            calls: self.container_calls.clone(),
            init_error: self.init_error,
        };
        session.record("anchor");
        Ok(session)
    }
}
impl ContainerSession for Session {
    fn make_root_shared(&mut self) -> Mutation {
        self.mutation("mount")
    }
    fn open_cgroups(&mut self) -> Result<CgroupLayout, ContainerError> {
        self.record("cgroup");
        Ok(CgroupLayout::V2)
    }
    fn ensure_init(&mut self) -> Mutation {
        self.record("init");
        Mutation {
            attempted: true,
            result: self.init_error.map_or(Ok(()), Err),
        }
    }
    fn migrate_current_process(&mut self) -> Mutation {
        self.mutation("migrate")
    }
    fn available_controllers(&mut self) -> Result<Vec<ControllerName>, ContainerError> {
        self.record("available");
        parse_controllers(b"cpu")
    }
    fn enabled_controllers(&mut self) -> Result<Vec<ControllerName>, ContainerError> {
        self.record("enabled");
        parse_controllers(b"cpu")
    }
    fn enable_controllers(&mut self, _: &[ControllerName]) -> Mutation {
        self.mutation("delegate")
    }
}
#[tokio::test]
async fn external_runtime_still_prepares_container_after_network_warnings() {
    let mut fake = Fake {
        module_outcome: CommandOutcome::Failed,
        ..Default::default()
    };
    let report =
        prepare_node_host_with(&config(true, true), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, HostPreparationStatus::Completed);
    assert_eq!(report.container.status, ContainerStatus::Completed);
    assert_eq!(
        *fake.container_calls.lock().unwrap(),
        [
            "anchor",
            "mount",
            "cgroup",
            "init",
            "migrate",
            "available",
            "enabled",
            "delegate",
            "enabled"
        ]
    );
    assert!(report.shared_effects_possible);
    assert!(
        report
            .network
            .modules
            .iter()
            .all(|step| step.command.outcome == CommandOutcome::Failed)
    );
}
#[tokio::test]
async fn resolved_noncontainer_mode_never_acquires_container_session() {
    let mut fake = Fake::default();
    let report =
        prepare_node_host_with(&config(false, false), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, HostPreparationStatus::Completed);
    assert_eq!(report.container.status, ContainerStatus::NotRequested);
    assert!(fake.container_calls.lock().unwrap().is_empty());
}
#[tokio::test]
async fn fresh_backend_guard_failure_prevents_all_effects() {
    let mut fake = Fake {
        family: Observation::Unknown(ProbeFailure::Malformed),
        ..Default::default()
    };
    let report =
        prepare_node_host_with(&config(false, true), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, HostPreparationStatus::GuardStopped);
    assert_eq!(
        fake.modules,
        <[diorama::host_network::ModuleId; 0]>::default()
    );
    assert!(fake.container_calls.lock().unwrap().is_empty());
    assert!(!report.shared_effects_possible);
}
#[tokio::test]
async fn uncertain_network_owner_stops_before_container_and_retains_effects() {
    let mut fake = Fake {
        unjoined: true,
        ..Default::default()
    };
    let report =
        prepare_node_host_with(&config(false, true), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, HostPreparationStatus::CleanupIncomplete);
    assert_eq!(report.network.modules.len(), 1);
    assert!(fake.container_calls.lock().unwrap().is_empty());
    assert!(report.shared_effects_possible);
}
#[tokio::test]
async fn network_cancellation_stops_before_container_and_retains_effects() {
    let mut fake = Fake {
        module_outcome: CommandOutcome::Cancelled,
        ..Default::default()
    };
    let report =
        prepare_node_host_with(&config(false, true), std::future::pending(), &mut fake).await;
    assert_eq!(report.status, HostPreparationStatus::Cancelled);
    assert_eq!(report.network.modules.len(), 1);
    assert!(fake.container_calls.lock().unwrap().is_empty());
    assert!(report.shared_effects_possible);
}
#[tokio::test]
async fn initially_cancelled_combined_operation_never_performs_effects() {
    let mut fake = Fake::default();
    let report = prepare_node_host_with(&config(false, true), async {}, &mut fake).await;
    assert_eq!(report.status, HostPreparationStatus::Cancelled);
    assert_eq!(
        fake.modules,
        <[diorama::host_network::ModuleId; 0]>::default()
    );
    assert!(fake.container_calls.lock().unwrap().is_empty());
    assert!(!report.shared_effects_possible);
}

#[tokio::test]
async fn repeatable_host_preparation_and_clean_failure_without_partial_service() {
    let mut fake = Fake {
        init_error: Some(ContainerError::Io),
        ..Fake::default()
    };
    let failed =
        prepare_node_host_with(&config(false, true), std::future::pending(), &mut fake).await;
    assert_eq!(failed.status, HostPreparationStatus::ContainerFailed);
    assert_eq!(
        failed.container.status,
        ContainerStatus::Fatal {
            stage: ContainerStage::Init,
            error: ContainerError::Io,
        }
    );
    let failed_calls = fake.container_calls.lock().unwrap().clone();
    assert!(failed_calls.contains(&"init"));
    assert!(
        !failed_calls
            .iter()
            .any(|call| { matches!(*call, "migrate" | "delegate") })
    );
    let modules_after_failure = fake.modules.len();
    assert_eq!(modules_after_failure, 12);

    fake.init_error = None;
    let repeated =
        prepare_node_host_with(&config(false, true), std::future::pending(), &mut fake).await;
    assert_eq!(repeated.status, HostPreparationStatus::Completed);
    assert_eq!(repeated.container.status, ContainerStatus::Completed);
    assert_eq!(fake.modules.len(), modules_after_failure + 12);
    let calls = fake.container_calls.lock().unwrap().clone();
    assert!(calls.contains(&"migrate"));
    assert!(calls.contains(&"delegate"));
}
