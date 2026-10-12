//! Explicit shared host-network effects. No startup, mounts, runtime or CNI ownership.
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use crate::host_preflight::{
    AssessmentInputs, AssessmentStatus, Cancellation, Host, NodeAssessment, assess_with_cancel,
};
use diorama_config::ValidatedConfig;
use diorama_platform::constrained::ModuleFamily;
use diorama_platform::{DiscoveryRequest, Observation, ProbeFailure, classify};
use diorama_supervisor::process::{
    OutputLimit, OutputSnapshot, OutputStatus, OwnedProcessAdapter, ProcessCleanup,
    ProcessCleanupSnapshot, ProcessCommand,
};
use diorama_supervisor::{
    AdapterError, ComponentKind, ComponentSpec, FailurePolicy, Registration, StopReceiver,
    Supervisor, stop_channel,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleId {
    BridgeNetfilter,
    Overlay,
    Comment,
    ConntrackMatch,
    Masquerade,
    AddressType,
    Multiport,
    NatMatch,
    NftCompat,
    NftNumgen,
    NftRedir,
    NftLimit,
    NftTproxy,
    IpTables,
    IpFilter,
    IpNat,
    Conntrack,
}
impl ModuleId {
    pub fn name(self) -> &'static str {
        match self {
            Self::BridgeNetfilter => "br_netfilter",
            Self::Overlay => "overlay",
            Self::Comment => "xt_comment",
            Self::ConntrackMatch => "xt_conntrack",
            Self::Masquerade => "xt_MASQUERADE",
            Self::AddressType => "xt_addrtype",
            Self::Multiport => "xt_multiport",
            Self::NatMatch => "xt_nat",
            Self::NftCompat => "nft_compat",
            Self::NftNumgen => "nft_numgen",
            Self::NftRedir => "nft_redir",
            Self::NftLimit => "nft_limit",
            Self::NftTproxy => "nft_tproxy",
            Self::IpTables => "ip_tables",
            Self::IpFilter => "iptable_filter",
            Self::IpNat => "iptable_nat",
            Self::Conntrack => "nf_conntrack",
        }
    }
}
const COMMON: [ModuleId; 8] = [
    ModuleId::BridgeNetfilter,
    ModuleId::Overlay,
    ModuleId::Comment,
    ModuleId::ConntrackMatch,
    ModuleId::Masquerade,
    ModuleId::AddressType,
    ModuleId::Multiport,
    ModuleId::NatMatch,
];
const NFT: [ModuleId; 5] = [
    ModuleId::NftCompat,
    ModuleId::NftNumgen,
    ModuleId::NftRedir,
    ModuleId::NftLimit,
    ModuleId::NftTproxy,
];
const LEGACY: [ModuleId; 4] = [
    ModuleId::IpTables,
    ModuleId::IpFilter,
    ModuleId::IpNat,
    ModuleId::Conntrack,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6Control {
    All,
    Default,
    Loopback,
}
impl Ipv6Control {
    pub fn path(self) -> &'static str {
        match self {
            Self::All => "/proc/sys/net/ipv6/conf/all/disable_ipv6",
            Self::Default => "/proc/sys/net/ipv6/conf/default/disable_ipv6",
            Self::Loopback => "/proc/sys/net/ipv6/conf/lo/disable_ipv6",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scalar {
    Enabled,
    Disabled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysctlError {
    Missing,
    PermissionDenied,
    Malformed,
    TooLarge,
    NotRegular,
    Io,
    Unsupported,
}
/// Complete ASCII scalar only, with surrounding ASCII whitespace; never first-byte matching.
pub fn parse_ipv6_scalar(bytes: &[u8]) -> Result<Scalar, SysctlError> {
    if bytes.len() > 64 {
        return Err(SysctlError::TooLarge);
    }
    match bytes.trim_ascii() {
        b"0" => Ok(Scalar::Enabled),
        b"1" => Ok(Scalar::Disabled),
        _ => Err(SysctlError::Malformed),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandOutcome {
    Success,
    Failed,
    Deadline,
    CaptureFailed,
    Cancelled,
    CleanupIncomplete,
}
#[derive(Debug)]
pub struct ModuleCommand {
    pub outcome: CommandOutcome,
    pub cleanup: ProcessCleanupSnapshot,
    pub observer: Option<ProcessCleanup>,
}
impl ModuleCommand {
    pub fn cleanup_uncertain(&self) -> bool {
        let c = &self.cleanup;
        if !c.started
            || (!c.spawned && !c.ownership_lost && c.error == Some("process_owner_spawn_failed"))
        {
            return false;
        }
        !c.thread_joined || (c.spawned && !c.leader_reaped) || c.ownership_lost
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleObservation {
    /// Exact names only; absent does not exclude a built-in implementation or alias.
    pub loaded: Observation<bool>,
    pub builtin_index: Observation<bool>,
    pub available_index: Observation<bool>,
}
#[derive(Debug)]
pub struct ModuleStep {
    pub module: ModuleId,
    pub command: ModuleCommand,
    /// None when cancellation or uncertain cleanup prevents further observation.
    pub after: Option<ModuleObservation>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ipv6Outcome {
    AlreadyDisabled,
    Skipped(SysctlError),
    Unreadable(SysctlError),
    WriteFailed(SysctlError),
    ObservedDisabled,
    Readback(Result<Scalar, SysctlError>),
    CancelledBeforeWrite,
    CancelledAfterWrite,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Step {
    pub control: Ipv6Control,
    pub outcome: Ipv6Outcome,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkStatus {
    Completed,
    GuardStopped,
    Cancelled,
    CleanupIncomplete,
}
#[derive(Debug)]
pub struct NetworkPreparation {
    pub status: NetworkStatus,
    pub assessment: NodeAssessment,
    pub modules: Vec<ModuleStep>,
    pub ipv6: Vec<Ipv6Step>,
    /// A spawned command or attempted write may change shared state, even on failure.
    pub shared_effects_possible: bool,
}
/// Trusted injected boundary for tests/embedders. No arbitrary command or path operation.
/// A command must settle owned cleanup or return explicit uncertainty with its observer.
pub trait NetworkPreparationInputs: AssessmentInputs {
    fn load_module(
        &mut self,
        module: ModuleId,
        stop: StopReceiver,
    ) -> impl Future<Output = ModuleCommand>;
    fn observe_module(&mut self, module: ModuleId) -> ModuleObservation;
    fn read_ipv6(&mut self, control: Ipv6Control) -> Result<Scalar, SysctlError>;
    fn write_ipv6_disabled(&mut self, control: Ipv6Control) -> Result<(), SysctlError>;
}
/// Calling this operation explicitly authorizes its fixed shared-network effects.
/// No listeners are installed; cancellation must remain owned through return.
pub async fn prepare_node_network(
    config: &ValidatedConfig,
    cancel: impl Future<Output = ()>,
) -> NetworkPreparation {
    prepare_node_network_with(config, cancel, &mut Host).await
}
pub async fn prepare_node_network_with(
    config: &ValidatedConfig,
    cancel: impl Future<Output = ()>,
    inputs: &mut impl NetworkPreparationInputs,
) -> NetworkPreparation {
    let mut cancel = Cancellation {
        future: Box::pin(cancel),
        stopped: false,
    };
    prepare_with_cancel(config, &mut cancel, inputs).await
}
pub(crate) async fn prepare_with_cancel<F: Future<Output = ()>>(
    config: &ValidatedConfig,
    cancel: &mut Cancellation<F>,
    inputs: &mut impl NetworkPreparationInputs,
) -> NetworkPreparation {
    let assessment = assess_with_cancel(config, cancel, inputs, true).await;
    let status = match assessment.status {
        AssessmentStatus::Cancelled => NetworkStatus::Cancelled,
        AssessmentStatus::CleanupIncomplete => NetworkStatus::CleanupIncomplete,
        _ => NetworkStatus::GuardStopped,
    };
    let mut report = NetworkPreparation {
        status,
        assessment,
        modules: Vec::with_capacity(13),
        ipv6: Vec::with_capacity(3),
        shared_effects_possible: false,
    };
    if report.assessment.status != AssessmentStatus::Observed {
        return report;
    }
    let Some(Observation::Present(family)) = report
        .assessment
        .constrained
        .as_ref()
        .map(|c| c.module_family)
    else {
        return report;
    };
    let backend: &[ModuleId] = match family {
        ModuleFamily::NfTables => &NFT,
        ModuleFamily::Legacy => &LEGACY,
    };
    for &module in COMMON.iter().chain(backend) {
        if cancel.checkpoint().await {
            report.status = NetworkStatus::Cancelled;
            return report;
        }
        let (stop, receiver) = stop_channel();
        let command = {
            let running = inputs.load_module(module, receiver);
            tokio::pin!(running);
            tokio::select! { biased;
                () = &mut cancel.future => { cancel.stopped = true; stop.stop(); running.await }
                result = &mut running => result,
            }
        };
        report.shared_effects_possible |= command.cleanup.spawned;
        let uncertain =
            command.cleanup_uncertain() || command.outcome == CommandOutcome::CleanupIncomplete;
        let cancelled = command.outcome == CommandOutcome::Cancelled;
        report.modules.push(ModuleStep {
            module,
            command,
            after: None,
        });
        if uncertain {
            report.status = NetworkStatus::CleanupIncomplete;
            return report;
        }
        if cancelled || cancel.checkpoint().await {
            report.status = NetworkStatus::Cancelled;
            return report;
        }
        let after = inputs.observe_module(module);
        if let Some(step) = report.modules.last_mut() {
            step.after = Some(after);
        }
    }
    if config.config().network.disable_ipv6 {
        prepare_ipv6(&mut report, cancel, inputs).await;
        if report.status == NetworkStatus::Cancelled {
            return report;
        }
    }
    report.status = if cancel.checkpoint().await {
        NetworkStatus::Cancelled
    } else {
        NetworkStatus::Completed
    };
    report
}

async fn prepare_ipv6<F: Future<Output = ()>>(
    report: &mut NetworkPreparation,
    cancel: &mut Cancellation<F>,
    inputs: &mut impl NetworkPreparationInputs,
) {
    for control in [
        Ipv6Control::All,
        Ipv6Control::Default,
        Ipv6Control::Loopback,
    ] {
        if cancel.checkpoint().await {
            report.status = NetworkStatus::Cancelled;
            return;
        }
        let outcome = match inputs.read_ipv6(control) {
            Ok(Scalar::Disabled) => Ipv6Outcome::AlreadyDisabled,
            Err(e @ (SysctlError::Missing | SysctlError::PermissionDenied)) => {
                Ipv6Outcome::Skipped(e)
            },
            Err(e) => Ipv6Outcome::Unreadable(e),
            Ok(Scalar::Enabled) => {
                if cancel.checkpoint().await {
                    report.ipv6.push(Ipv6Step {
                        control,
                        outcome: Ipv6Outcome::CancelledBeforeWrite,
                    });
                    report.status = NetworkStatus::Cancelled;
                    return;
                }
                report.shared_effects_possible = true;
                let result = inputs.write_ipv6_disabled(control);
                if cancel.checkpoint().await {
                    report.ipv6.push(Ipv6Step {
                        control,
                        outcome: Ipv6Outcome::CancelledAfterWrite,
                    });
                    report.status = NetworkStatus::Cancelled;
                    return;
                }
                match result {
                    Err(e) => Ipv6Outcome::WriteFailed(e),
                    Ok(()) => match inputs.read_ipv6(control) {
                        Ok(Scalar::Disabled) => Ipv6Outcome::ObservedDisabled,
                        other => Ipv6Outcome::Readback(other),
                    },
                }
            },
        };
        report.ipv6.push(Ipv6Step { control, outcome });
    }
}

fn mapped<T>(value: Observation<Vec<T>>, predicate: impl Fn(&T) -> bool) -> Observation<bool> {
    match value {
        Observation::Present(items) => Observation::Present(items.iter().any(predicate)),
        Observation::Absent => Observation::Absent,
        Observation::Unknown(e) => Observation::Unknown(e),
    }
}
fn exact_module(path: &Path, module: ModuleId) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let name = name
        .strip_suffix(".zst")
        .or_else(|| name.strip_suffix(".xz"))
        .or_else(|| name.strip_suffix(".gz"))
        .unwrap_or(name);
    name.strip_suffix(".ko") == Some(module.name())
}
impl NetworkPreparationInputs for Host {
    async fn load_module(&mut self, module: ModuleId, stop: StopReceiver) -> ModuleCommand {
        modprobe(module, stop).await
    }
    fn observe_module(&mut self, module: ModuleId) -> ModuleObservation {
        let Ok(evidence) = self.discover(&DiscoveryRequest::default()) else {
            return ModuleObservation {
                loaded: Observation::Unknown(ProbeFailure::Io),
                builtin_index: Observation::Unknown(ProbeFailure::Io),
                available_index: Observation::Unknown(ProbeFailure::Io),
            };
        };
        let facts = classify(&evidence);
        ModuleObservation {
            loaded: mapped(facts.loaded_modules, |name| name == module.name()),
            builtin_index: mapped(facts.builtin_modules, |path| exact_module(path, module)),
            available_index: mapped(facts.available_modules, |item| {
                exact_module(&item.path, module)
            }),
        }
    }
    fn read_ipv6(&mut self, control: Ipv6Control) -> Result<Scalar, SysctlError> {
        sysctl_io::read(control)
    }
    fn write_ipv6_disabled(&mut self, control: Ipv6Control) -> Result<(), SysctlError> {
        sysctl_io::write(control)
    }
}
async fn modprobe(module: ModuleId, stop: StopReceiver) -> ModuleCommand {
    let command = ProcessCommand::new("modprobe")
        .arg(module.name())
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .current_dir("/");
    let (adapter, observer, output) = OwnedProcessAdapter::new_with_bounded_output(
        command,
        async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Err(AdapterError {
                code: "network_module_deadline",
            })
        },
        OutputLimit::new(4096).expect("constant output limit"),
    );
    let spec = ComponentSpec {
        id: "network-module".into(),
        prerequisites: vec![],
        kind: ComponentKind::OneShot,
        failure_policy: FailurePolicy::Fatal,
        startup_timeout: Duration::from_secs(6),
    };
    let Ok(supervisor) = Supervisor::new(vec![Registration::new(spec, adapter)]) else {
        return ModuleCommand {
            outcome: CommandOutcome::Failed,
            cleanup: observer.snapshot(),
            observer: Some(observer),
        };
    };
    let result = supervisor.run(stop).await;
    let cleanup = observer.wait(Duration::from_secs(1)).await;
    let mut receipt = ModuleCommand {
        outcome: CommandOutcome::Failed,
        cleanup,
        observer: Some(observer),
    };
    receipt.outcome = if receipt.cleanup_uncertain() {
        CommandOutcome::CleanupIncomplete
    } else if matches!(
        result.cause,
        diorama_supervisor::StopCause::Requested | diorama_supervisor::StopCause::ControlClosed
    ) {
        CommandOutcome::Cancelled
    } else if result.failures.iter().any(|f| {
        matches!(
            f.kind,
            diorama_supervisor::FailureKind::Adapter("network_module_deadline")
                | diorama_supervisor::FailureKind::StartupTimeout
        )
    }) {
        CommandOutcome::Deadline
    } else {
        match output.snapshot() {
            OutputSnapshot::Finished(bytes) if bytes.status == OutputStatus::Complete => {
                if receipt.cleanup.complete()
                    && receipt.cleanup.exit.is_some_and(|e| e.code == Some(0))
                    && result.failures.is_empty()
                    && result.cleanup_failures.is_empty()
                {
                    CommandOutcome::Success
                } else {
                    CommandOutcome::Failed
                }
            },
            OutputSnapshot::Finished(bytes)
                if bytes.status == OutputStatus::SpawnFailed
                    || receipt.cleanup.error == Some("process_owner_spawn_failed") =>
            {
                CommandOutcome::Failed
            },
            _ => CommandOutcome::CaptureFailed,
        }
    };
    receipt
}
#[cfg(target_os = "linux")]
mod sysctl_io {
    use super::{Ipv6Control, Scalar, SysctlError, parse_ipv6_scalar};
    use rustix::fs::{Mode, OFlags, open};
    use std::fs::File;
    use std::io::{self, Read, Write};
    fn error(kind: io::ErrorKind) -> SysctlError {
        match kind {
            io::ErrorKind::NotFound => SysctlError::Missing,
            io::ErrorKind::PermissionDenied => SysctlError::PermissionDenied,
            _ => SysctlError::Io,
        }
    }
    fn file(control: Ipv6Control, access: OFlags) -> Result<File, SysctlError> {
        let fd = open(
            control.path(),
            access | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
        )
        .map_err(|e| error(io::Error::from(e).kind()))?;
        let file = File::from(fd);
        if !file.metadata().map_err(|e| error(e.kind()))?.is_file() {
            return Err(SysctlError::NotRegular);
        }
        Ok(file)
    }
    pub(super) fn read(control: Ipv6Control) -> Result<Scalar, SysctlError> {
        let mut bytes = Vec::with_capacity(65);
        file(control, OFlags::RDONLY)?
            .take(65)
            .read_to_end(&mut bytes)
            .map_err(|e| error(e.kind()))?;
        parse_ipv6_scalar(&bytes)
    }
    pub(super) fn write(control: Ipv6Control) -> Result<(), SysctlError> {
        let mut file = file(control, OFlags::WRONLY)?;
        if file.write(b"1").map_err(|e| error(e.kind()))? != 1 {
            return Err(SysctlError::Io);
        }
        Ok(())
    }
}
#[cfg(not(target_os = "linux"))]
mod sysctl_io {
    use super::{Ipv6Control, Scalar, SysctlError};
    pub(super) fn read(_: Ipv6Control) -> Result<Scalar, SysctlError> {
        Err(SysctlError::Unsupported)
    }
    pub(super) fn write(_: Ipv6Control) -> Result<(), SysctlError> {
        Err(SysctlError::Unsupported)
    }
}
