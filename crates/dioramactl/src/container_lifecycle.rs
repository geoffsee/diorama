//! Named-instance status and start/stop/restart/remove primitives for container mode.
//!
//! Every operation derives resource names from the selected instance, so a second
//! instance's container, network and volume are never touched. The data volume holds
//! persisted state and is retained unless `purge` is requested.

use crate::container::{
    ContainerEngineClient, PublishedEndpoints, container_name, network_name, published_endpoints,
    volume_name,
};
use std::fmt;

const STOP_TIMEOUT_SECS: u32 = 30;

/// Observed run state of a named instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceState {
    Absent,
    Running,
    Stopped { exit_code: i64 },
}

/// Status snapshot of a named instance and its owned resources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceStatus {
    pub instance_name: String,
    pub state: InstanceState,
    pub container_id: Option<String>,
    pub endpoints: Option<PublishedEndpoints>,
    pub network_present: bool,
    pub volume_present: bool,
}

/// Outcome of a removal; failures do not abort the remaining owned removals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RemoveReport {
    pub removed: Vec<String>,
    pub failures: Vec<String>,
}

impl RemoveReport {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Lifecycle operation failures.
#[derive(Debug)]
pub enum InstanceError {
    NotFound(String),
    Engine(String),
}

impl fmt::Display for InstanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(n) => write!(f, "instance \"{n}\" does not exist"),
            Self::Engine(e) => write!(f, "container engine error: {e}"),
        }
    }
}

impl std::error::Error for InstanceError {}

fn engine_err(op: &str, e: &std::io::Error) -> InstanceError {
    InstanceError::Engine(format!("{op}: {e}"))
}

/// Reports the state, published endpoints and owned resources of an instance.
///
/// # Errors
/// Returns an error when the engine cannot be inspected.
pub fn instance_status(
    engine: &mut dyn ContainerEngineClient,
    instance: &str,
) -> Result<InstanceStatus, InstanceError> {
    let inspect = engine
        .inspect_container(&container_name(instance))
        .map_err(|e| engine_err("container inspect failed", &e))?;
    let network_present = engine
        .inspect_network(&network_name(instance))
        .map_err(|e| engine_err("network inspect failed", &e))?
        .is_some();
    let volume_present = engine
        .inspect_volume(&volume_name(instance))
        .map_err(|e| engine_err("volume inspect failed", &e))?
        .is_some();
    let (state, container_id, endpoints) = match inspect {
        None => (InstanceState::Absent, None, None),
        Some(c) if c.running => {
            let eps = published_endpoints(&c);
            (InstanceState::Running, Some(c.id), eps)
        },
        Some(c) => (
            InstanceState::Stopped {
                exit_code: i64::from(c.exit_code),
            },
            Some(c.id),
            None,
        ),
    };
    Ok(InstanceStatus {
        instance_name: instance.to_string(),
        state,
        container_id,
        endpoints,
        network_present,
        volume_present,
    })
}

/// Starts a stopped instance; a running instance is left unchanged.
///
/// # Errors
/// Fails when the instance does not exist or the engine rejects the start.
pub fn start_instance(
    engine: &mut dyn ContainerEngineClient,
    instance: &str,
) -> Result<InstanceStatus, InstanceError> {
    let cname = container_name(instance);
    let existing = engine
        .inspect_container(&cname)
        .map_err(|e| engine_err("container inspect failed", &e))?
        .ok_or_else(|| InstanceError::NotFound(instance.to_string()))?;
    if !existing.running {
        engine
            .start_container(&cname)
            .map_err(|e| engine_err("container start failed", &e))?;
    }
    instance_status(engine, instance)
}

/// Stops a running instance, retaining container, network and volume.
///
/// # Errors
/// Fails when the instance does not exist or the engine rejects the stop.
pub fn stop_instance(
    engine: &mut dyn ContainerEngineClient,
    instance: &str,
) -> Result<InstanceStatus, InstanceError> {
    let cname = container_name(instance);
    let existing = engine
        .inspect_container(&cname)
        .map_err(|e| engine_err("container inspect failed", &e))?
        .ok_or_else(|| InstanceError::NotFound(instance.to_string()))?;
    if existing.running {
        engine
            .stop_container(&cname, STOP_TIMEOUT_SECS)
            .map_err(|e| engine_err("container stop failed", &e))?;
    }
    instance_status(engine, instance)
}

/// Restarts an instance in place, preserving its configuration and volume mount.
///
/// # Errors
/// Fails when the instance does not exist or stop/start fails.
pub fn restart_instance(
    engine: &mut dyn ContainerEngineClient,
    instance: &str,
) -> Result<InstanceStatus, InstanceError> {
    stop_instance(engine, instance)?;
    start_instance(engine, instance)
}

/// Removes only the selected instance's container, and with `purge` its network and
/// data volume. Continues past individual failures and reports them.
pub fn remove_instance(
    engine: &mut dyn ContainerEngineClient,
    instance: &str,
    purge: bool,
) -> RemoveReport {
    let mut report = RemoveReport::default();
    let cname = container_name(instance);
    match engine.inspect_container(&cname) {
        Ok(Some(_)) => match engine.remove_container(&cname, true) {
            Ok(()) => report.removed.push(format!("container {cname}")),
            Err(e) => report.failures.push(format!("container {cname}: {e}")),
        },
        Ok(None) => {},
        Err(e) => report.failures.push(format!("container {cname}: {e}")),
    }
    if purge {
        let nname = network_name(instance);
        match engine.inspect_network(&nname) {
            Ok(Some(_)) => match engine.remove_network(&nname) {
                Ok(()) => report.removed.push(format!("network {nname}")),
                Err(e) => report.failures.push(format!("network {nname}: {e}")),
            },
            Ok(None) => {},
            Err(e) => report
                .failures
                .push(format!("network {nname} inspection: {e}")),
        }
        let vname = volume_name(instance);
        match engine.inspect_volume(&vname) {
            Ok(Some(())) => match engine.remove_volume(&vname) {
                Ok(()) => report.removed.push(format!("volume {vname}")),
                Err(e) => report.failures.push(format!("volume {vname}: {e}")),
            },
            Ok(None) => {},
            Err(e) => report
                .failures
                .push(format!("volume {vname} inspection: {e}")),
        }
    }
    report
}
