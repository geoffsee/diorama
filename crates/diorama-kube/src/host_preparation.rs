//! Explicit ordered host preparation; production startup does not invoke this API.
use std::future::Future;

use crate::host_container::{
    self, ContainerPreparation, ContainerPreparationInputs, ContainerStatus,
};
use crate::host_network::{self, NetworkPreparation, NetworkPreparationInputs, NetworkStatus};
use crate::host_preflight::{Cancellation, Host, RequirementState};
use diorama_config::ValidatedConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPreparationStatus {
    Completed,
    GuardStopped,
    Cancelled,
    CleanupIncomplete,
    ContainerFailed,
}
#[derive(Debug)]
pub struct HostPreparation {
    pub status: HostPreparationStatus,
    pub network: NetworkPreparation,
    pub container: ContainerPreparation,
    pub shared_effects_possible: bool,
}
/// Authorizes fixed network and (when resolved container mode requires it) mount/cgroup
/// effects. Requires quiescent startup: no child spawning, namespace/root changes or
/// concurrent mount/cgroup mutations, and homogeneous executor thread namespaces.
/// No rollback, runtime start, listeners, filesystem installation or CRI operations.
/// Cancellation must stay owned through return, including network process settlement.
pub async fn prepare_node_host(
    config: &ValidatedConfig,
    cancel: impl Future<Output = ()>,
) -> HostPreparation {
    prepare_node_host_with(config, cancel, &mut Host).await
}
pub async fn prepare_node_host_with(
    config: &ValidatedConfig,
    cancel: impl Future<Output = ()>,
    inputs: &mut (impl NetworkPreparationInputs + ContainerPreparationInputs),
) -> HostPreparation {
    let mut cancel = Cancellation {
        future: Box::pin(cancel),
        stopped: false,
    };
    let network = host_network::prepare_with_cancel(config, &mut cancel, inputs).await;
    let status = match network.status {
        NetworkStatus::Completed => HostPreparationStatus::Completed,
        NetworkStatus::GuardStopped => HostPreparationStatus::GuardStopped,
        NetworkStatus::Cancelled => HostPreparationStatus::Cancelled,
        NetworkStatus::CleanupIncomplete => HostPreparationStatus::CleanupIncomplete,
    };
    let mut report = HostPreparation {
        status,
        shared_effects_possible: network.shared_effects_possible,
        network,
        container: ContainerPreparation::default(),
    };
    if status != HostPreparationStatus::Completed {
        return report;
    }
    match report.network.assessment.container_preparation {
        RequirementState::NotRequested => report.container.status = ContainerStatus::NotRequested,
        RequirementState::Unknown(_) => report.status = HostPreparationStatus::GuardStopped,
        RequirementState::Required => {
            report.container = host_container::prepare(&mut cancel, inputs).await;
            report.shared_effects_possible |= report.container.shared_effects_possible;
            report.status = match report.container.status {
                ContainerStatus::Completed => HostPreparationStatus::Completed,
                ContainerStatus::Cancelled => HostPreparationStatus::Cancelled,
                _ => HostPreparationStatus::ContainerFailed,
            };
        },
    }
    report
}
