//! External CRI runtime supervisor service adapter.
//!
//! Attaches to pre-existing host-managed CRI runtimes (containerd or CRI-O)
//! without spawning child processes, extracting local payload archives, or
//! managing host daemon lifecycles.

use crate::endpoint::RuntimeEndpoints;
use crate::provider::ProviderInfo;
use crate::readiness::{
    DEFAULT_READINESS_TIMEOUT, DEFAULT_RETRY_INTERVAL, ReadinessError, probe_cri_readiness,
};
use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, StopPhase,
};
use std::fmt;
use std::time::Duration;

pub const COMPONENT_EXTERNAL_CRI: &str = "external-cri";

/// Configuration options for attaching to an external CRI runtime.
#[derive(Clone, Debug)]
pub struct ExternalRuntimeOptions {
    pub endpoints: RuntimeEndpoints,
    pub readiness_timeout: Duration,
    pub retry_interval: Duration,
}

impl ExternalRuntimeOptions {
    pub fn new(endpoints: RuntimeEndpoints) -> Self {
        Self {
            endpoints,
            readiness_timeout: DEFAULT_READINESS_TIMEOUT,
            retry_interval: DEFAULT_RETRY_INTERVAL,
        }
    }
}

/// Supervised service adapter for external CRI runtimes.
pub struct ExternalRuntimeService {
    options: ExternalRuntimeOptions,
}

impl fmt::Debug for ExternalRuntimeService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalRuntimeService")
            .field("endpoints", &self.options.endpoints)
            .finish()
    }
}

impl ExternalRuntimeService {
    pub fn new(options: ExternalRuntimeOptions) -> Self {
        Self { options }
    }

    /// Build component specification for supervisor registration.
    pub fn component_spec(startup_timeout: Duration) -> ComponentSpec {
        ComponentSpec {
            id: COMPONENT_EXTERNAL_CRI.into(),
            prerequisites: Vec::new(),
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Fatal,
            startup_timeout,
        }
    }

    /// Performs readiness verification against external runtime and image endpoints.
    pub async fn probe(&self) -> Result<ProviderInfo, ReadinessError> {
        probe_cri_readiness(
            &self.options.endpoints,
            self.options.readiness_timeout,
            self.options.retry_interval,
        )
        .await
    }
}

impl Adapter for ExternalRuntimeService {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            if context.stop_phase() != StopPhase::Running {
                return Ok(());
            }

            tokio::select! {
                probe_res = self.probe() => {
                    let _provider_info = probe_res.map_err(|_| AdapterError {
                        code: "external_cri_readiness_failed",
                    })?;
                    context.ready();
                }
                phase = context.changed() => {
                    if phase != StopPhase::Running {
                        return Ok(());
                    }
                }
            }

            // External mode: stay alive until shutdown is signaled.
            // Does not start, stop, or manage the host process.
            while context.changed().await == StopPhase::Running {}
            Ok(())
        })
    }
}
