//! Pure host preflight policy. Plans describe work; this module never executes it.
use crate::{HostEvidence, Observation, ProbeFailure};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeOwnership {
    Managed,
    External,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortAvailability {
    Available,
    BindFailed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightInputs {
    pub install_prerequisites: bool,
    pub pprof: bool,
    pub runtime: RuntimeOwnership,
    /// Actual baseline candidate/glob existence, not modules.dep/index evidence.
    pub xt_comment_on_disk: Observation<bool>,
    /// Existence at exactly /sbin/rc-service, independent of init classification.
    pub alpine_rc_service: Observation<bool>,
    /// Actual wildcard TCP bind observations, ordered 2379, 6443, 10443, 6060.
    /// A prior observation never reserves a port or promises future bind success.
    pub ports: [Observation<PortAvailability>; 4],
}
impl Default for PreflightInputs {
    fn default() -> Self {
        Self {
            install_prerequisites: false,
            pprof: false,
            runtime: RuntimeOwnership::Managed,
            xt_comment_on_disk: Observation::Unknown(ProbeFailure::Malformed),
            alpine_rc_service: Observation::Unknown(ProbeFailure::Malformed),
            ports: [Observation::Unknown(ProbeFailure::Malformed); 4],
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckId {
    Root,
    Hostname,
    DockerConflict,
    XtablesComment,
    AlpineNetworking,
    Cgroups,
    Ports,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    NotApplicable,
    Blocker,
    Unknown,
    NeedsPreparation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Satisfied,
    NotAlpine,
    MissingObservation,
    ProbeFailed,
    RootRequired,
    HostnameEmpty,
    HostnameTooLong,
    HostnameEmptyLabel,
    HostnameLabelTooLong,
    HostnameInvalidLabel,
    DockerSocketPresent,
    DockerBinaryPresent,
    CommentSupportMissing,
    AlpineToolsMissing,
    AlpineCgroupsSetup,
    CgroupsAbsent,
    ControllersMissing,
    PortsBindFailed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requirement {
    Nftables,
    Iptables,
    Cpuset,
    Cpu,
    Io,
    Memory,
    Pids,
    Port2379,
    Port6443,
    Port10443,
    Port6060,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationAction {
    InstallAlpineNetworking { nftables: bool, iptables: bool },
    EnableAlpineCgroups,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remediation {
    RunAsRoot,
    ConfigureHostname,
    ResolveDockerConflict,
    ProvideCommentSupport,
    InstallAlpineNetworking,
    EnableAlpineCgroups,
    EnableKernelControllers,
    ResolvePortConflict,
    ObtainObservation,
    RecheckAfterPreparation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorSeverity {
    Fatal,
    Recoverable,
    /// The check could not be observed. This is not a confirmed incompatible host.
    Uncertain,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub check: CheckId,
    pub status: CheckStatus,
    pub reason: Reason,
    pub missing: Vec<Requirement>,
    pub uncertainty: Option<ProbeFailure>,
    pub remediation: Option<Remediation>,
    pub plans: Vec<PreparationAction>,
}
impl Finding {
    pub fn severity(&self) -> Option<ErrorSeverity> {
        match self.status {
            CheckStatus::Pass | CheckStatus::NotApplicable => None,
            CheckStatus::NeedsPreparation => Some(ErrorSeverity::Recoverable),
            CheckStatus::Blocker => match self.reason {
                Reason::AlpineToolsMissing | Reason::AlpineCgroupsSetup => {
                    Some(ErrorSeverity::Recoverable)
                },
                _ => Some(ErrorSeverity::Fatal),
            },
            CheckStatus::Unknown => Some(ErrorSeverity::Uncertain),
        }
    }

    pub fn is_fatal(&self) -> bool {
        self.severity() == Some(ErrorSeverity::Fatal)
    }

    pub fn is_recoverable(&self) -> bool {
        self.severity() == Some(ErrorSeverity::Recoverable)
    }

    pub fn is_uncertain(&self) -> bool {
        self.severity() == Some(ErrorSeverity::Uncertain)
    }

    fn new(check: CheckId, status: CheckStatus, reason: Reason) -> Self {
        Self {
            check,
            status,
            reason,
            missing: vec![],
            uncertainty: None,
            remediation: None,
            plans: vec![],
        }
    }
    fn pass(check: CheckId) -> Self {
        Self::new(check, CheckStatus::Pass, Reason::Satisfied)
    }
    fn blocked(check: CheckId, reason: Reason, remediation: Remediation) -> Self {
        Self {
            remediation: Some(remediation),
            ..Self::new(check, CheckStatus::Blocker, reason)
        }
    }
    fn unknown(check: CheckId, failure: Option<ProbeFailure>) -> Self {
        Self {
            uncertainty: failure,
            remediation: Some(Remediation::ObtainObservation),
            ..Self::new(
                check,
                CheckStatus::Unknown,
                if failure.is_some() {
                    Reason::ProbeFailed
                } else {
                    Reason::MissingObservation
                },
            )
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightReport {
    pub findings: [Finding; 7],
    /// First non-passing check in baseline suite order, including unknown/unprepared.
    pub first_blocker: Option<CheckId>,
    pub runtime: RuntimeOwnership,
}
impl PreflightReport {
    pub fn ready(&self) -> bool {
        self.first_blocker.is_none()
    }

    pub fn fatal_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.is_fatal())
    }

    pub fn recoverable_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.is_recoverable())
    }

    pub fn uncertain_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.is_uncertain())
    }

    pub fn has_fatal_errors(&self) -> bool {
        self.findings.iter().any(Finding::is_fatal)
    }

    pub fn has_recoverable_limitations(&self) -> bool {
        self.findings.iter().any(Finding::is_recoverable)
    }

    pub fn has_uncertain_observations(&self) -> bool {
        self.findings.iter().any(Finding::is_uncertain)
    }
}
fn landmark(e: &HostEvidence, path: &str) -> Observation<bool> {
    e.landmarks
        .get(path)
        .copied()
        .unwrap_or(Observation::Unknown(ProbeFailure::Malformed))
}
fn any(values: impl IntoIterator<Item = Observation<bool>>) -> Observation<bool> {
    let mut unknown = None;
    for value in values {
        match value {
            Observation::Present(true) => return Observation::Present(true),
            Observation::Unknown(error) => {
                unknown.get_or_insert(error);
            },
            Observation::Absent | Observation::Present(false) => {},
        }
    }
    unknown.map_or(Observation::Present(false), Observation::Unknown)
}
fn root(e: &HostEvidence) -> Finding {
    match e.privileges {
        Observation::Present(p) if p.real_uid == 0 => Finding::pass(CheckId::Root),
        Observation::Present(_) => {
            Finding::blocked(CheckId::Root, Reason::RootRequired, Remediation::RunAsRoot)
        },
        Observation::Absent => Finding::unknown(CheckId::Root, None),
        Observation::Unknown(error) => Finding::unknown(CheckId::Root, Some(error)),
    }
}
/// Baseline raw-hostname check: no trimming, normalization, or fallback identity.
pub fn hostname_reason(hostname: &str) -> Option<Reason> {
    if hostname.is_empty() {
        return Some(Reason::HostnameEmpty);
    }
    if hostname.len() > 253 {
        return Some(Reason::HostnameTooLong);
    }
    for label in hostname.split('.') {
        if label.is_empty() {
            return Some(Reason::HostnameEmptyLabel);
        }
        if label.len() > 63 {
            return Some(Reason::HostnameLabelTooLong);
        }
        let alnum = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if !label.bytes().all(|byte| alnum(byte) || byte == b'-')
            || !alnum(label.as_bytes()[0])
            || !alnum(label.as_bytes()[label.len() - 1])
        {
            return Some(Reason::HostnameInvalidLabel);
        }
    }
    None
}
fn hostname(e: &HostEvidence) -> Finding {
    match &e.hostname {
        Observation::Present(value) => hostname_reason(value).map_or_else(
            || Finding::pass(CheckId::Hostname),
            |reason| Finding::blocked(CheckId::Hostname, reason, Remediation::ConfigureHostname),
        ),
        Observation::Absent => Finding::unknown(CheckId::Hostname, None),
        Observation::Unknown(error) => Finding::unknown(CheckId::Hostname, Some(*error)),
    }
}
fn docker(e: &HostEvidence) -> Finding {
    let mut unknown = None;
    for (path, reason) in [
        ("/var/run/docker.sock", Reason::DockerSocketPresent),
        ("/usr/bin/docker", Reason::DockerBinaryPresent),
        ("/usr/local/bin/docker", Reason::DockerBinaryPresent),
    ] {
        match landmark(e, path) {
            Observation::Present(true) => {
                return Finding::blocked(
                    CheckId::DockerConflict,
                    reason,
                    Remediation::ResolveDockerConflict,
                );
            },
            Observation::Unknown(error) => {
                unknown.get_or_insert(error);
            },
            _ => {},
        }
    }
    unknown.map_or_else(
        || Finding::pass(CheckId::DockerConflict),
        |error| Finding::unknown(CheckId::DockerConflict, Some(error)),
    )
}
fn comment(e: &HostEvidence, inputs: &PreflightInputs) -> Finding {
    // Match the baseline's line scanner, not a stricter full /proc/modules parser.
    let loaded = match e.files.get("/proc/modules") {
        Some(Observation::Present(text)) => Observation::Present(
            text.lines()
                .any(|line| line.split_whitespace().next() == Some("xt_comment")),
        ),
        Some(Observation::Absent) => Observation::Absent,
        Some(Observation::Unknown(error)) => Observation::Unknown(*error),
        None => Observation::Unknown(ProbeFailure::Malformed),
    };
    let matched = match e.files.get("/proc/net/ip_tables_matches") {
        Some(Observation::Present(text)) => {
            Observation::Present(text.lines().any(|line| line.trim() == "comment"))
        },
        Some(Observation::Absent) => Observation::Absent,
        Some(Observation::Unknown(error)) => Observation::Unknown(*error),
        None => Observation::Unknown(ProbeFailure::Malformed),
    };
    match any([loaded, matched, inputs.xt_comment_on_disk]) {
        Observation::Present(true) => Finding::pass(CheckId::XtablesComment),
        Observation::Unknown(error) => Finding::unknown(CheckId::XtablesComment, Some(error)),
        _ => Finding::blocked(
            CheckId::XtablesComment,
            Reason::CommentSupportMissing,
            Remediation::ProvideCommentSupport,
        ),
    }
}
fn alpine(e: &HostEvidence) -> Observation<bool> {
    landmark(e, "/etc/alpine-release")
}
fn networking(e: &HostEvidence, inputs: &PreflightInputs) -> Finding {
    match alpine(e) {
        Observation::Absent | Observation::Present(false) => {
            return Finding::new(
                CheckId::AlpineNetworking,
                CheckStatus::NotApplicable,
                Reason::NotAlpine,
            );
        },
        Observation::Unknown(error) => {
            return Finding::unknown(CheckId::AlpineNetworking, Some(error));
        },
        Observation::Present(true) => {},
    }
    let nft = any(["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"].map(|p| landmark(e, p)));
    let ipt = any([
        "/sbin/iptables",
        "/usr/sbin/iptables",
        "/bin/iptables",
        "/usr/bin/iptables",
    ]
    .map(|p| landmark(e, p)));
    for value in [nft, ipt] {
        if let Observation::Unknown(error) = value {
            return Finding::unknown(CheckId::AlpineNetworking, Some(error));
        }
    }
    let nft = nft == Observation::Present(true);
    let ipt = ipt == Observation::Present(true);
    if nft && ipt {
        return Finding::pass(CheckId::AlpineNetworking);
    }
    let mut finding = Finding::blocked(
        CheckId::AlpineNetworking,
        Reason::AlpineToolsMissing,
        Remediation::InstallAlpineNetworking,
    );
    if !nft {
        finding.missing.push(Requirement::Nftables);
    }
    if !ipt {
        finding.missing.push(Requirement::Iptables);
    }
    if inputs.install_prerequisites {
        finding.status = CheckStatus::NeedsPreparation;
        finding
            .plans
            .push(PreparationAction::InstallAlpineNetworking {
                nftables: !nft,
                iptables: !ipt,
            });
        finding.remediation = Some(Remediation::RecheckAfterPreparation);
    }
    finding
}
const CONTROLLERS: [(&str, Requirement); 5] = [
    ("cpuset", Requirement::Cpuset),
    ("cpu", Requirement::Cpu),
    ("io", Requirement::Io),
    ("memory", Requirement::Memory),
    ("pids", Requirement::Pids),
];
fn cgroups(e: &HostEvidence, inputs: &PreflightInputs) -> Finding {
    let controllers = e.files.get("/sys/fs/cgroup/cgroup.controllers");
    match controllers {
        None => return Finding::unknown(CheckId::Cgroups, None),
        Some(Observation::Unknown(error)) => {
            return Finding::unknown(CheckId::Cgroups, Some(*error));
        },
        _ => {},
    }
    let is_alpine = alpine(e);
    let nonempty = matches!(controllers,Some(Observation::Present(text)) if text.split_whitespace().next().is_some());
    if !nonempty {
        match is_alpine {
            Observation::Unknown(error) => return Finding::unknown(CheckId::Cgroups, Some(error)),
            Observation::Present(true) => match inputs.alpine_rc_service {
                Observation::Present(true) => {
                    let mut finding = Finding::blocked(
                        CheckId::Cgroups,
                        Reason::AlpineCgroupsSetup,
                        Remediation::EnableAlpineCgroups,
                    );
                    if inputs.install_prerequisites {
                        finding.status = CheckStatus::NeedsPreparation;
                        finding.plans.push(PreparationAction::EnableAlpineCgroups);
                        finding.remediation = Some(Remediation::RecheckAfterPreparation);
                    }
                    return finding;
                },
                Observation::Unknown(error) => {
                    return Finding::unknown(CheckId::Cgroups, Some(error));
                },
                _ => {},
            },
            _ => {},
        }
    }
    let mut missing = Vec::new();
    match controllers {
        Some(Observation::Present(text)) => {
            for (name, requirement) in CONTROLLERS {
                if !text.split_whitespace().any(|value| value == name) {
                    missing.push(requirement);
                }
            }
        },
        Some(Observation::Unknown(error)) => {
            return Finding::unknown(CheckId::Cgroups, Some(*error));
        },
        None => return Finding::unknown(CheckId::Cgroups, None),
        Some(Observation::Absent) => {
            match landmark(e, "/sys/fs/cgroup") {
                Observation::Present(true) => {},
                Observation::Unknown(error) => {
                    return Finding::unknown(CheckId::Cgroups, Some(error));
                },
                _ => {
                    return Finding::blocked(
                        CheckId::Cgroups,
                        Reason::CgroupsAbsent,
                        Remediation::EnableKernelControllers,
                    );
                },
            }
            for (name, requirement) in CONTROLLERS {
                let directory = if name == "io" { "blkio" } else { name };
                match landmark(e, &format!("/sys/fs/cgroup/{directory}")) {
                    Observation::Present(true) => {},
                    Observation::Unknown(error) => {
                        return Finding::unknown(CheckId::Cgroups, Some(error));
                    },
                    _ => missing.push(requirement),
                }
            }
        },
    }
    if missing.is_empty() {
        Finding::pass(CheckId::Cgroups)
    } else {
        Finding {
            missing,
            ..Finding::blocked(
                CheckId::Cgroups,
                Reason::ControllersMissing,
                Remediation::EnableKernelControllers,
            )
        }
    }
}
fn ports(inputs: &PreflightInputs) -> Finding {
    let required = if inputs.pprof { 4 } else { 3 };
    let mut finding = Finding::pass(CheckId::Ports);
    let mut unknown = None;
    let mut absent = false;
    for (observation, requirement) in inputs.ports[..required].iter().zip([
        Requirement::Port2379,
        Requirement::Port6443,
        Requirement::Port10443,
        Requirement::Port6060,
    ]) {
        match observation {
            Observation::Present(PortAvailability::Available) => {},
            Observation::Present(PortAvailability::BindFailed) => finding.missing.push(requirement),
            Observation::Unknown(error) => {
                unknown.get_or_insert(*error);
            },
            Observation::Absent => absent = true,
        }
    }
    if !finding.missing.is_empty() {
        finding.status = CheckStatus::Blocker;
        finding.reason = Reason::PortsBindFailed;
        finding.remediation = Some(Remediation::ResolvePortConflict);
        finding.uncertainty = unknown;
    } else if unknown.is_some() || absent {
        return Finding::unknown(CheckId::Ports, unknown);
    }
    finding
}
/// Evaluate all seven checks without effects, retaining baseline order and first
/// blocker for a fail-fast presentation. No readiness claim until every required
/// observation passes; a proposed preparation still requires execution and recheck.
pub fn evaluate_preflight(evidence: &HostEvidence, inputs: &PreflightInputs) -> PreflightReport {
    let findings = [
        root(evidence),
        hostname(evidence),
        docker(evidence),
        comment(evidence, inputs),
        networking(evidence, inputs),
        cgroups(evidence, inputs),
        ports(inputs),
    ];
    let first_blocker = findings
        .iter()
        .find(|f| !matches!(f.status, CheckStatus::Pass | CheckStatus::NotApplicable))
        .map(|f| f.check);
    PreflightReport {
        findings,
        first_blocker,
        runtime: inputs.runtime,
    }
}
