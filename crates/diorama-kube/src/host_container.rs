//! Fixed container host effects, invoked only after fresh network preparation.
//!
//! Callers must quiesce process spawning and namespace/root/mount changes. All executor
//! threads must use the intended namespaces. Revalidation detects changes; it is not
//! a lock against concurrent namespace or topology changes. Existing children are not
//! migrated. Synchronous kernel calls are bounded in data, not in elapsed time.
use std::future::Future;

use crate::host_preflight::Cancellation;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerError {
    UnsupportedPlatform,
    UnsupportedKernel,
    UnsupportedRootType,
    Missing,
    PermissionDenied,
    ReadOnly,
    WrongType,
    WrongFilesystem,
    Malformed,
    TooLarge,
    ShortWrite,
    Io,
    /// An anchor/admission changed, or could no longer be revalidated.
    ContextChanged,
    MountReadbackUncertain,
    MembershipNotAdmitted,
    MigrationUnobserved,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerStage {
    Anchor,
    Mount,
    CgroupRoot,
    Init,
    Migration,
    Controllers,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerStatus {
    NotStarted,
    NotRequested,
    Completed,
    Cancelled,
    Fatal {
        stage: ContainerStage,
        error: ContainerError,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupLayout {
    V1,
    V2,
}
/// Attempt means the mutating syscall was reached, including a failed syscall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mutation {
    pub attempted: bool,
    pub result: Result<(), ContainerError>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ControllerName(String);
impl ControllerName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
/// Complete bounded kernel-token set; never accepts operators, paths, or duplicates.
pub fn parse_controllers(bytes: &[u8]) -> Result<Vec<ControllerName>, ContainerError> {
    if bytes.len() > 4096 {
        return Err(ContainerError::TooLarge);
    }
    let mut names = Vec::new();
    for name in bytes
        .split(u8::is_ascii_whitespace)
        .filter(|s| !s.is_empty())
    {
        if names.len() == 32 || name.len() > 64 {
            return Err(ContainerError::TooLarge);
        }
        if !name[0].is_ascii_lowercase()
            || !name
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
        {
            return Err(ContainerError::Malformed);
        }
        let name = ControllerName(
            String::from_utf8(name.to_vec()).map_err(|_| ContainerError::Malformed)?,
        );
        if names.contains(&name) {
            return Err(ContainerError::Malformed);
        }
        names.push(name);
    }
    Ok(names)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerAttempt {
    /// Empty only for the bulk attempt on an empty available set (no write needed).
    pub controllers: Vec<ControllerName>,
    pub mutation: Mutation,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerPreparation {
    pub status: ContainerStatus,
    pub mount: Option<Mutation>,
    pub layout: Option<CgroupLayout>,
    pub init: Option<Mutation>,
    pub migration: Option<Mutation>,
    pub available: Vec<ControllerName>,
    pub enabled_before: Vec<ControllerName>,
    pub controller_attempts: Vec<ControllerAttempt>,
    /// A write's success is never substituted for this independent observation.
    pub enabled_after: Option<Result<Vec<ControllerName>, ContainerError>>,
    pub missing_after: Vec<ControllerName>,
    pub shared_effects_possible: bool,
}
impl Default for ContainerPreparation {
    fn default() -> Self {
        Self {
            status: ContainerStatus::NotStarted,
            mount: None,
            layout: None,
            init: None,
            migration: None,
            available: Vec::new(),
            enabled_before: Vec::new(),
            controller_attempts: Vec::new(),
            enabled_after: None,
            missing_after: Vec::new(),
            shared_effects_possible: false,
        }
    }
}
/// Trusted injected boundary. Operations use fixed paths and the current process PID.
/// Each mutating method must revalidate its executing thread's namespace/root anchors
/// synchronously, and return `attempted=false` if authorization failed before the syscall.
/// `make_root_shared` must verify the complete anchored mount tree after the syscall.
/// `open_cgroups` admits only cgroup2 domain roots containing this process at root/init;
/// positively identified cgroup1 is the sole skip case. `migrate_current_process` must
/// independently observe the actual process in init before returning success.
pub trait ContainerSession {
    fn make_root_shared(&mut self) -> Mutation;
    fn open_cgroups(&mut self) -> Result<CgroupLayout, ContainerError>;
    fn ensure_init(&mut self) -> Mutation;
    fn migrate_current_process(&mut self) -> Mutation;
    fn available_controllers(&mut self) -> Result<Vec<ControllerName>, ContainerError>;
    fn enabled_controllers(&mut self) -> Result<Vec<ControllerName>, ContainerError>;
    fn enable_controllers(&mut self, names: &[ControllerName]) -> Mutation;
}
pub trait ContainerPreparationInputs {
    type Session: ContainerSession;
    /// Read-only anchor capture, after network effects have settled.
    fn container_session(&mut self) -> Result<Self::Session, ContainerError>;
}
fn controller_fatal(error: ContainerError) -> bool {
    !matches!(
        error,
        ContainerError::PermissionDenied
            | ContainerError::ReadOnly
            | ContainerError::Io
            | ContainerError::ShortWrite
    )
}
fn fatal(report: &mut ContainerPreparation, stage: ContainerStage, error: ContainerError) {
    report.status = ContainerStatus::Fatal { stage, error };
}
async fn cancelled<F: Future<Output = ()>>(
    report: &mut ContainerPreparation,
    cancel: &mut Cancellation<F>,
) -> bool {
    if cancel.checkpoint().await {
        report.status = ContainerStatus::Cancelled;
        true
    } else {
        false
    }
}
pub(crate) async fn prepare<F: Future<Output = ()>>(
    cancel: &mut Cancellation<F>,
    inputs: &mut impl ContainerPreparationInputs,
) -> ContainerPreparation {
    let mut report = ContainerPreparation::default();
    if cancelled(&mut report, cancel).await {
        return report;
    }
    let mut session = match inputs.container_session() {
        Ok(session) => session,
        Err(error) => {
            fatal(&mut report, ContainerStage::Anchor, error);
            return report;
        },
    };
    if cancelled(&mut report, cancel).await {
        return report;
    }
    let mutation = session.make_root_shared();
    report.shared_effects_possible |= mutation.attempted;
    let result = mutation.result;
    report.mount = Some(mutation);
    if let Err(error) = result {
        fatal(&mut report, ContainerStage::Mount, error);
        return report;
    }
    if cancelled(&mut report, cancel).await {
        return report;
    }
    match session.open_cgroups() {
        Ok(layout) => report.layout = Some(layout),
        Err(error) => {
            fatal(&mut report, ContainerStage::CgroupRoot, error);
            return report;
        },
    }
    if report.layout == Some(CgroupLayout::V1) {
        if !cancelled(&mut report, cancel).await {
            report.status = ContainerStatus::Completed;
        }
        return report;
    }
    if cancelled(&mut report, cancel).await {
        return report;
    }
    let mutation = session.ensure_init();
    report.shared_effects_possible |= mutation.attempted;
    let result = mutation.result;
    report.init = Some(mutation);
    if let Err(error) = result {
        fatal(&mut report, ContainerStage::Init, error);
        return report;
    }
    if cancelled(&mut report, cancel).await {
        return report;
    }
    let mutation = session.migrate_current_process();
    report.shared_effects_possible |= mutation.attempted;
    let result = mutation.result;
    report.migration = Some(mutation);
    if let Err(error) = result {
        fatal(&mut report, ContainerStage::Migration, error);
        return report;
    }
    if cancelled(&mut report, cancel).await {
        return report;
    }
    delegate(&mut report, cancel, &mut session).await;
    report
}
fn record_attempt(
    report: &mut ContainerPreparation,
    names: Vec<ControllerName>,
    mutation: Mutation,
) -> Result<bool, ContainerError> {
    report.shared_effects_possible |= mutation.attempted;
    let result = mutation.result;
    report.controller_attempts.push(ControllerAttempt {
        controllers: names,
        mutation,
    });
    match result {
        Err(error) if controller_fatal(error) => Err(error),
        Err(_) => Ok(true),
        Ok(()) => Ok(false),
    }
}
async fn delegate<F: Future<Output = ()>>(
    report: &mut ContainerPreparation,
    cancel: &mut Cancellation<F>,
    session: &mut impl ContainerSession,
) {
    match session.available_controllers() {
        Ok(names) => report.available = names,
        Err(error) => {
            fatal(report, ContainerStage::Controllers, error);
            return;
        },
    }
    if cancelled(report, cancel).await {
        return;
    }
    match session.enabled_controllers() {
        Ok(names) => report.enabled_before = names,
        Err(error) => {
            fatal(report, ContainerStage::Controllers, error);
            return;
        },
    }
    if cancelled(report, cancel).await {
        return;
    }
    let names = report.available.clone();
    if !names.is_empty() {
        let mutation = session.enable_controllers(&names);
        let fallback = match record_attempt(report, names, mutation) {
            Ok(fallback) => fallback,
            Err(error) => {
                fatal(report, ContainerStage::Controllers, error);
                return;
            },
        };
        if fallback {
            for name in report.available.clone() {
                if cancelled(report, cancel).await {
                    return;
                }
                let names = vec![name];
                let mutation = session.enable_controllers(&names);
                if let Err(error) = record_attempt(report, names, mutation) {
                    fatal(report, ContainerStage::Controllers, error);
                    return;
                }
            }
        }
    }
    if cancelled(report, cancel).await {
        return;
    }
    let observed = session.enabled_controllers();
    if let Ok(ref names) = observed {
        report.missing_after = report
            .available
            .iter()
            .filter(|name| !names.contains(name))
            .cloned()
            .collect();
    }
    let context_changed = observed == Err(ContainerError::ContextChanged);
    report.enabled_after = Some(observed);
    if context_changed {
        fatal(
            report,
            ContainerStage::Controllers,
            ContainerError::ContextChanged,
        );
    } else if !cancelled(report, cancel).await {
        report.status = ContainerStatus::Completed;
    }
}

#[cfg(target_os = "linux")]
#[path = "host_container_linux.rs"]
mod platform;
#[cfg(target_os = "linux")]
impl ContainerPreparationInputs for crate::host_preflight::Host {
    type Session = platform::LinuxSession;
    fn container_session(&mut self) -> Result<Self::Session, ContainerError> {
        platform::LinuxSession::open()
    }
}
#[cfg(not(target_os = "linux"))]
impl ContainerPreparationInputs for crate::host_preflight::Host {
    type Session = UnsupportedSession;
    fn container_session(&mut self) -> Result<Self::Session, ContainerError> {
        Err(ContainerError::UnsupportedPlatform)
    }
}
#[cfg(not(target_os = "linux"))]
pub(crate) struct UnsupportedSession;
#[cfg(not(target_os = "linux"))]
impl ContainerSession for UnsupportedSession {
    fn make_root_shared(&mut self) -> Mutation {
        Mutation {
            attempted: false,
            result: Err(ContainerError::UnsupportedPlatform),
        }
    }
    fn open_cgroups(&mut self) -> Result<CgroupLayout, ContainerError> {
        Err(ContainerError::UnsupportedPlatform)
    }
    fn ensure_init(&mut self) -> Mutation {
        self.make_root_shared()
    }
    fn migrate_current_process(&mut self) -> Mutation {
        self.make_root_shared()
    }
    fn available_controllers(&mut self) -> Result<Vec<ControllerName>, ContainerError> {
        Err(ContainerError::UnsupportedPlatform)
    }
    fn enabled_controllers(&mut self) -> Result<Vec<ControllerName>, ContainerError> {
        Err(ContainerError::UnsupportedPlatform)
    }
    fn enable_controllers(&mut self, _: &[ControllerName]) -> Mutation {
        self.make_root_shared()
    }
}

#[cfg(test)]
#[path = "host_container_tests.rs"]
mod tests;
