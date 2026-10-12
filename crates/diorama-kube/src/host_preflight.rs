//! Explicit node assessment; never called implicitly by the unfinished startup executable.
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use diorama_config::ValidatedConfig;
use diorama_platform::constrained::{
    ConstrainedFacts, ConstrainedInputs, ConstrainedReport, ModuleFamily, SysctlState,
    collect_constrained, evaluate_constrained,
};
use diorama_platform::preflight::{
    CheckId, CheckStatus, PortAvailability, PreflightInputs, PreflightReport, RuntimeOwnership,
    evaluate_preflight,
};
use diorama_platform::preflight_probe::{SupplementalFacts, collect_supplemental, probe_ports};
use diorama_platform::{
    DiscoveryRequest, HostEvidence, Observation, PlatformError, ProbeFailure, ProbeLimits,
    classify, discover,
};
use diorama_supervisor::process::{
    OutputLimit, OutputSnapshot, OutputStatus, OwnedProcessAdapter, ProcessCleanup,
    ProcessCleanupSnapshot, ProcessCommand,
};
use diorama_supervisor::{
    AdapterError, ComponentKind, ComponentSpec, FailurePolicy, Registration, StopReceiver,
    Supervisor, stop_channel,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionFailure {
    Command,
    Deadline,
    Capture,
    Cleanup,
    Cancelled,
}
#[derive(Debug)]
pub struct VersionProbe {
    pub family: Observation<ModuleFamily>,
    pub failure: Option<VersionFailure>,
    pub cleanup: ProcessCleanupSnapshot,
    /// Retain for later observation if cleanup is incomplete; no signaling capability.
    pub observer: Option<ProcessCleanup>,
}
impl VersionProbe {
    pub fn cleanup_uncertain(&self) -> bool {
        if !self.cleanup.started || self.owner_launch_failed() {
            return false;
        }
        !self.cleanup.thread_joined
            || (self.cleanup.spawned && !self.cleanup.leader_reaped)
            || self.cleanup.ownership_lost
    }
    fn owner_launch_failed(&self) -> bool {
        !self.cleanup.spawned
            && !self.cleanup.ownership_lost
            && self.cleanup.error == Some("process_owner_spawn_failed")
    }
    fn terminal_owner_failure(&self) -> Option<VersionFailure> {
        if self.cleanup_uncertain() {
            Some(VersionFailure::Cleanup)
        } else if self.owner_launch_failed() {
            Some(VersionFailure::Command)
        } else {
            None
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssessmentStatus {
    Observed,
    Blocked,
    Unknown,
    Cancelled,
    CleanupIncomplete,
    Platform(PlatformError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequirementState {
    NotRequested,
    Required,
    Unknown(ProbeFailure),
}
#[derive(Debug)]
pub struct NodeAssessment {
    pub status: AssessmentStatus,
    pub runtime: RuntimeOwnership,
    pub container_mode: Observation<bool>,
    /// Requirements only. No root mount propagation or current-node PID move is performed.
    pub container_preparation: RequirementState,
    pub ipv6_disable: [Option<SysctlState>; 3],
    pub preflight: Option<PreflightReport>,
    pub constrained: Option<ConstrainedReport>,
    pub version: Option<VersionProbe>,
}
impl NodeAssessment {
    fn initial(config: &ValidatedConfig) -> Self {
        Self {
            status: AssessmentStatus::Unknown,
            runtime: if config.config().runtime.endpoint.trim().is_empty() {
                RuntimeOwnership::Managed
            } else {
                RuntimeOwnership::External
            },
            container_mode: Observation::Unknown(ProbeFailure::Malformed),
            container_preparation: RequirementState::Unknown(ProbeFailure::Malformed),
            ipv6_disable: [None; 3],
            preflight: None,
            constrained: None,
            version: None,
        }
    }
}
/// Implementations provide observations and one fixed probe, never preparation or node startup.
/// The version future must retain owned cleanup after receiving stop; raw output stays private.
pub trait AssessmentInputs {
    fn discover(&mut self, request: &DiscoveryRequest) -> Result<HostEvidence, PlatformError>;
    fn supplemental(&mut self, limits: ProbeLimits) -> Result<SupplementalFacts, PlatformError>;
    fn constrained(&mut self, limits: ProbeLimits) -> Result<ConstrainedFacts, PlatformError>;
    fn ports(&mut self, pprof: bool) -> Result<[Observation<PortAvailability>; 4], PlatformError>;
    fn version(&mut self, stop: StopReceiver) -> impl Future<Output = VersionProbe>;
}
pub(crate) struct Host;
impl AssessmentInputs for Host {
    fn discover(&mut self, request: &DiscoveryRequest) -> Result<HostEvidence, PlatformError> {
        discover(request)
    }
    fn supplemental(&mut self, limits: ProbeLimits) -> Result<SupplementalFacts, PlatformError> {
        collect_supplemental(limits)
    }
    fn constrained(&mut self, limits: ProbeLimits) -> Result<ConstrainedFacts, PlatformError> {
        collect_constrained(limits)
    }
    fn ports(&mut self, pprof: bool) -> Result<[Observation<PortAvailability>; 4], PlatformError> {
        probe_ports(pprof)
    }
    async fn version(&mut self, stop: StopReceiver) -> VersionProbe {
        iptables_version(stop).await
    }
}
pub(crate) struct Cancellation<F> {
    pub(crate) future: Pin<Box<F>>,
    pub(crate) stopped: bool,
}
impl<F: Future<Output = ()>> Cancellation<F> {
    pub(crate) async fn checkpoint(&mut self) -> bool {
        if !self.stopped {
            tokio::select! { biased; () = &mut self.future => self.stopped = true, () = tokio::task::yield_now() => {} }
        }
        self.stopped
    }
}
/// Observe this configuration explicitly. No signal handlers are installed by this library.
/// Synchronous filesystem observations cannot be preempted; cancellation wins between phases.
pub async fn assess_node(
    config: &ValidatedConfig,
    cancellation: impl Future<Output = ()>,
) -> NodeAssessment {
    assess_node_with(config, cancellation, &mut Host).await
}
pub async fn assess_node_with(
    config: &ValidatedConfig,
    cancellation: impl Future<Output = ()>,
    inputs: &mut impl AssessmentInputs,
) -> NodeAssessment {
    let mut cancel = Cancellation {
        future: Box::pin(cancellation),
        stopped: false,
    };
    assess_with_cancel(config, &mut cancel, inputs, false).await
}

pub(crate) async fn assess_with_cancel<F: Future<Output = ()>>(
    config: &ValidatedConfig,
    cancel: &mut Cancellation<F>,
    inputs: &mut impl AssessmentInputs,
    defer_ipv6: bool,
) -> NodeAssessment {
    let mut report = NodeAssessment::initial(config);
    if let Err(error) = observe(config, inputs, cancel, &mut report, defer_ipv6).await {
        report.status = AssessmentStatus::Platform(error);
    }
    report
}
async fn checkpoint<F: Future<Output = ()>>(
    cancel: &mut Cancellation<F>,
    report: &mut NodeAssessment,
) -> bool {
    if cancel.checkpoint().await {
        report.status = AssessmentStatus::Cancelled;
        false
    } else {
        true
    }
}
fn observe_container(
    config: &ValidatedConfig,
    evidence: &HostEvidence,
    report: &mut NodeAssessment,
) {
    let capabilities = classify(evidence);
    report.container_mode = config
        .config()
        .runtime
        .container_mode
        .map_or(capabilities.runtime_container, Observation::Present);
    report.container_preparation = match report.container_mode {
        Observation::Present(true) => RequirementState::Required,
        Observation::Present(false) => RequirementState::NotRequested,
        Observation::Unknown(error) => RequirementState::Unknown(error),
        Observation::Absent => RequirementState::Unknown(ProbeFailure::Malformed),
    };
}
async fn observe<F: Future<Output = ()>>(
    config: &ValidatedConfig,
    inputs: &mut impl AssessmentInputs,
    cancel: &mut Cancellation<F>,
    report: &mut NodeAssessment,
    defer_ipv6: bool,
) -> Result<(), PlatformError> {
    let limits = ProbeLimits::default();
    if !checkpoint(cancel, report).await {
        return Ok(());
    }
    let evidence = inputs.discover(&DiscoveryRequest {
        paths: vec![config.config().path.clone().into()],
        limits,
    })?;
    observe_container(config, &evidence, report);
    if !checkpoint(cancel, report).await {
        return Ok(());
    }
    let supplemental = inputs.supplemental(limits)?;
    let mut policy = PreflightInputs {
        pprof: config.config().logging.pprof,
        runtime: report.runtime,
        xt_comment_on_disk: supplemental.xt_comment_on_disk,
        alpine_rc_service: supplemental.alpine_rc_service,
        ..PreflightInputs::default()
    };
    let preflight = evaluate_preflight(&evidence, &policy);
    let earlier_blocker = preflight
        .first_blocker
        .is_some_and(|id| id != CheckId::Ports);
    let comment = preflight
        .findings
        .iter()
        .find(|finding| finding.check == CheckId::XtablesComment)
        .map_or(CheckStatus::Unknown, |finding| finding.status);
    report.preflight = Some(preflight);
    if earlier_blocker {
        report.status = AssessmentStatus::Blocked;
        return Ok(());
    }
    if !checkpoint(cancel, report).await {
        return Ok(());
    }
    let facts = inputs.constrained(limits)?;
    let mut constrained = evaluate_constrained(
        &facts,
        &ConstrainedInputs {
            runtime: report.runtime,
            iptables_version: Observation::Unknown(ProbeFailure::Malformed),
            xtables_comment: comment,
        },
    );
    if config.config().network.disable_ipv6 {
        report.ipv6_disable = std::array::from_fn(|i| Some(constrained.sysctls[i + 1]));
    }
    // Unrequested IPv6 disable observations remain raw facts, not preparation requirements.
    let unknown = matches!(
        report.container_mode,
        Observation::Unknown(_) | Observation::Absent
    ) || matches!(constrained.proxy_selection, Observation::Unknown(_))
        || matches!(constrained.sysctls[0], SysctlState::Unknown(_))
        || (!defer_ipv6
            && report
                .ipv6_disable
                .iter()
                .any(|value| matches!(value, Some(SysctlState::Unknown(_)))));
    if unknown {
        report.constrained = Some(constrained);
        report.status = AssessmentStatus::Unknown;
        return Ok(());
    }
    if !checkpoint(cancel, report).await {
        return Ok(());
    }
    let version = run_version(inputs, cancel).await;
    let uncertain = version.cleanup_uncertain();
    constrained.module_family = version.family;
    report.constrained = Some(constrained);
    let failed = version.failure.is_some() || !matches!(version.family, Observation::Present(_));
    report.version = Some(version);
    if uncertain {
        report.status = AssessmentStatus::CleanupIncomplete;
        return Ok(());
    }
    if !checkpoint(cancel, report).await {
        return Ok(());
    }
    if failed {
        report.status = AssessmentStatus::Unknown;
        return Ok(());
    }
    policy.ports = inputs.ports(policy.pprof)?;
    if !checkpoint(cancel, report).await {
        return Ok(());
    }
    let preflight = evaluate_preflight(&evidence, &policy);
    report.status = if preflight.ready() {
        AssessmentStatus::Observed
    } else {
        AssessmentStatus::Blocked
    };
    report.preflight = Some(preflight);
    Ok(())
}
async fn run_version<F: Future<Output = ()>>(
    inputs: &mut impl AssessmentInputs,
    cancel: &mut Cancellation<F>,
) -> VersionProbe {
    let (stop, receiver) = stop_channel();
    let running = inputs.version(receiver);
    tokio::pin!(running);
    tokio::select! { biased;
        () = &mut cancel.future => { cancel.stopped = true; stop.stop(); running.await }
        result = &mut running => result,
    }
}
/// Only the reviewed fixed command is executable here; no caller-controlled argv or environment.
pub async fn iptables_version(stop: StopReceiver) -> VersionProbe {
    let command = ProcessCommand::new("iptables")
        .arg("--version")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .current_dir("/");
    let (adapter, observer, output) = OwnedProcessAdapter::new_with_bounded_output(
        command,
        async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Err(AdapterError {
                code: "iptables_probe_deadline",
            })
        },
        OutputLimit::new(4096).expect("constant bounded output"),
    );
    let spec = ComponentSpec {
        id: "iptables-version".into(),
        prerequisites: vec![],
        kind: ComponentKind::OneShot,
        failure_policy: FailurePolicy::Fatal,
        startup_timeout: Duration::from_secs(3),
    };
    let Ok(supervisor) = Supervisor::new(vec![Registration::new(spec, adapter)]) else {
        return VersionProbe {
            family: Observation::Unknown(ProbeFailure::Io),
            failure: Some(VersionFailure::Deadline),
            cleanup: observer.snapshot(),
            observer: Some(observer),
        };
    };
    let result = supervisor.run(stop).await;
    let cleanup = observer.wait(Duration::from_secs(1)).await;
    let mut probe = VersionProbe {
        family: Observation::Unknown(ProbeFailure::Io),
        failure: Some(VersionFailure::Command),
        cleanup,
        observer: Some(observer),
    };
    if let Some(failure) = probe.terminal_owner_failure() {
        probe.failure = Some(failure);
        return probe;
    }
    if matches!(
        result.cause,
        diorama_supervisor::StopCause::Requested | diorama_supervisor::StopCause::ControlClosed
    ) {
        probe.failure = Some(VersionFailure::Cancelled);
        return probe;
    }
    if result.failures.iter().any(|failure| {
        matches!(
            failure.kind,
            diorama_supervisor::FailureKind::Adapter("iptables_probe_deadline")
                | diorama_supervisor::FailureKind::StartupTimeout
        )
    }) {
        probe.failure = Some(VersionFailure::Deadline);
        return probe;
    }
    let OutputSnapshot::Finished(bytes) = output.snapshot() else {
        probe.failure = Some(VersionFailure::Capture);
        return probe;
    };
    if bytes.status == OutputStatus::SpawnFailed {
        return probe;
    }
    if bytes.status != OutputStatus::Complete {
        probe.failure = Some(VersionFailure::Capture);
        return probe;
    }
    if !probe.cleanup.complete()
        || probe.cleanup.exit.is_none_or(|exit| exit.code != Some(0))
        || !result.failures.is_empty()
        || !result.cleanup_failures.is_empty()
    {
        return probe;
    }
    probe.family = Observation::Present(
        if bytes
            .bytes()
            .windows(b"(nf_tables)".len())
            .any(|part| part == b"(nf_tables)")
        {
            ModuleFamily::NfTables
        } else {
            ModuleFamily::Legacy
        },
    );
    probe.failure = None;
    probe
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_launch_failure_is_command_failure_but_unfinished_owner_is_uncertain() {
        let mut probe = VersionProbe {
            family: Observation::Unknown(ProbeFailure::Io),
            failure: None,
            cleanup: ProcessCleanupSnapshot {
                started: true,
                error: Some("process_owner_spawn_failed"),
                ..Default::default()
            },
            observer: None,
        };
        assert_eq!(
            probe.terminal_owner_failure(),
            Some(VersionFailure::Command)
        );
        assert!(!probe.cleanup_uncertain());
        probe.cleanup.error = None;
        assert_eq!(
            probe.terminal_owner_failure(),
            Some(VersionFailure::Cleanup)
        );
        probe.cleanup.error = Some("process_owner_spawn_failed");
        probe.cleanup.ownership_lost = true;
        assert_eq!(
            probe.terminal_owner_failure(),
            Some(VersionFailure::Cleanup)
        );
    }
}
